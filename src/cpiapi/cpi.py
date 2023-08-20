#! /usr/bin/python3
# cpi.py library Copyright 2019 by Dennis Risen, Case Western Reserve University
#
"""
Cpi class reads CPI's APIs
Cache class manages a json file cache of recently read CPI API data
"""

""" TODO
Cisco now appears to be correctly populating queryResponse['entity'][i]['@dtoType']
with dto_name={variant of api name}DTO. Verify with all API that it is correct
and use it, rather than the dot_names[:] guesses.

Unless the __init__ supplies a semaphore, it attempts to create another Cpi with
the same server and user as an existing instance will return the existing instance.
I.e. use constructor or metaclass=Unique.

Obtain and install certificate for ncs01.case.edu

Better support concurrent communications with differently configured servers by
refactoring rateWait, maxResults, ... from the class to the server instance.
"""
# requires urllib3[secure]

from collections.abc import Generator
from typing import Callable, Union
import json
import requests
import os
import pprint
import sys
import time
import urllib3

# direct threading is Panda3d's incompatible alternative for threading
# if 'direct.stdpy.threading' in sys.modules:
#     import direct.stdpy.threading as threading
# else:
import threading
from mylib import credentials, logErr
# import certifi        # fix certificate handling later *****


class Cpi:
    """A Cisco Prime Infrastructure server instance."""
    # Default values, shared by all instances
    rateWait = 1                    # seconds to wait to clear service busy
    maxResults = 1000               # maximum number of results per GET
    TIMEOUT = 80.0                  # seconds to wait between packets
    timeDelta = 0.0         # my epochSeconds === server's epochSeconds+timeDelta
    POSTING_DELTA = 6*60.0  # CPI posts record in database <= 6*60 seconds of event
    # rate limiting attributes
    segmentSize = .100              # seconds per window segment
    windowSize = 1.000              # seconds in CPI rate-limiting window
    perUserThreshold = 5            # Max # of user requests allowed per window
    maxConcurrent = 5               # Number of concurrent GETs allowed
    max_timeout = 3600              # Max seconds of retrying before ConnectionError

    def __init__(self, username: str, password: str,
                 baseURL: str = "https://ncs01.case.edu/webacs/api/",
                 semaphore: Union[threading.Semaphore, None] = None):
        """Create a CPI server instance with username, password, and server base URL.

        :param username:    username to use on the designated server
        :param password:    password
        :param baseURL:     https URL of the api base on the server
        :param semaphore:   Use this semaphore, rather than internal, for each GET
        """
        self.username = username
        self.password = password
        self.baseURL = baseURL          # URL of the server APIs
        self.history = []               # epochSeconds of each recent request to CPI
        self.semaphore = semaphore if semaphore else threading.Semaphore()  # for multi-thread locking
        self.rate_semaphore = threading.Semaphore(self.maxConcurrent)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # ***** until certificates are installed

    def rateLimit(self):
        """Sleep as necessary to limit requests per ``windowSize`` in msec."""
        # CPI stores the history of requests in segmentSize buckets
        # CPI's and my buckets may be out of sync by as much as segmentSize
        # so pad tests by segmentSize
        self.rate_semaphore.acquire()   # limit concurrent requests to maxConcurrent
        self.semaphore.acquire()        # critical section for manipulating history
        t = time.time()                 # current epochSeconds
        while len(self.history) > 0 and self.history[0] < t - (self.windowSize + self.segmentSize):
            del self.history[0]         # remove request older than windowSize
        if len(self.history) >= self.perUserThreshold:
            dt = self.windowSize + self.segmentSize - (t - self.history[-self.perUserThreshold])
            if dt > 0.0:
                self.semaphore.release()  # exit critical section before sleep
                time.sleep(dt)          # until < threshold requests in window
                self.semaphore.acquire()  # critical section for manipulating history
                t = time.time()
        self.history.append(t)          # add this request to the history
        self.semaphore.release()        # exit critical section

    def setTimeDelta(self, delta: float) -> 'Cpi':
        """Sets default seconds offset < (my epochSeconds - server's epochSeconds).

        If the server is dynamically adding records to the API data while the client
        is reading data, and the client has no better way of filtering for new
        records than using the server's timestamp, a significant skew between the
        client's and server's clock could cause failure to collect some new records.

        :param delta:   lower estimate of my time.time() - server' time.time()
        :return:        updated self
        """
        self.timeDelta = delta
        return self

    class Reader:
        """Reader for Cisco Prime Infrastructure APIs
        """
        def __init__(self, server: 'Cpi', tableURL: str, filters: dict = None,
                     verbose: int = 0, pager: Union[Callable, None] = None, paged: bool = True):
            """Create Reader to GET all records from an API

            :param server:      a Cisco Prime Infrastructure instance
            :param tableURL:    API URL relative to baseURL
            :param filters:     additional filtering to apply in the URL
            :param verbose:     diagnostic messaging level
            :param pager:       results paging manager
            :param paged:       True if the table API implements paging
            """
            self.tableURL = tableURL    # API URL relative to baseURL
            self.filters = filters if filters else {}
            self.server = server        # Cisco Prime Infrastructure instance
            self.verbose = verbose      # diagnostic messaging level
            self.pager = pager if pager else self.defaultPager
            self.paged = paged          # whether the API supports paging
            self.recCnt = 0             # number of records retrieved so far
            self.pager('init')          # initialize pager
            # The listEntityInstances @responseType's entity is a list of instances.
            # Each instance should have a @dtoType which should be the key for the
            # instance's dict of attribute values.
            # However, the @dtoType value has not reliably been the correct key.
            # This Reader calculates two guesses for the correct value, based on
            # the API name. dto_names[0] is the guess that most recently worked.
            self.dto_names = []         # list of guesses for the DTO name
            self.four_oh_one = 0        # number of consecutive 401 unauthorized
            self.cpi_crud = 0           # ***** num of consecutive 500 crud from API

        def __iter__(self) -> Generator:  # the iterator. 1st next() starts it
            """Parse through (possibly paged) GET(s) yielding one record at a time.

            :return:    yields self.result = requests.get(...)
                dict: attribute:value pairs
                :raises ConnectionError
                :raises ConnectionAbortedError on consistent internal server error
                :raises ConnectionRefusedError
                :raises TypeError on invalid response format
            """
            self.backoff = 1  # scale factor for diag_sleep. 2x for each consecutive
            self.sleepingSeconds = 0    # Total seconds spent sleeping
            self.errorSeconds = 0       # Consecutive seconds of sleep from errors
            self.recCnt = 0             # number of records retrieved so far
            self.four_oh_one = 0        # no consecutive 401 Unauthorized Exceptions
            self.cpi_crud = 0           # ***** as yet no 500 crud status-code
            while True:                 # for each page or record until EOF
                filters = {'.full': 'true'}
                if self.paged:
                    filters['.maxResults'] = str(self.server.maxResults)
                # filters['.maxResults'] = str(80)
                # add in the paging filters
                x = self.pager('filter')
                for k in x:
                    filters[k] = x[k]
                # add in the caller's filters
                for k, v in self.filters.items():
                    filters[k] = v
                self.server.rateLimit()  # sleep as necessary to avoid over-running CPI
                if self.verbose > 0:
                    print(f"  filters={filters}", flush=True)
                try:
                    r = requests.get(self.server.baseURL + self.tableURL + '.json',
                                     auth=(self.server.username, self.server.password),
                                     verify=False, params=filters, timeout=self.server.TIMEOUT)
                except requests.exceptions.ReadTimeout:
                    self.server.rate_semaphore.release()  # release concurrent count
                    logErr(self.diag_str(None, f"{sys.exc_info()[0]} {sys.exc_info()[1]}\n") + self.diag_sleep(30))
                    continue
                except requests.exceptions.RequestException:  # e.g. [ConnectionError|TooManyRedirects]
                    self.server.rate_semaphore.release()  # release concurrent count
                    logErr(self.diag_str(None, f"{sys.exc_info()[0]} {sys.exc_info()[1]}\n") + self.diag_sleep(4*60))
                    continue            # Could possibly clear. try again

                # Doc. states that error responses are coded as requested (JSON)
                # However, status_codes 401, 403, and 404 and 403 return HTML
                self.server.rate_semaphore.release()  # release concurrent count
                try:
                    response = r.json()
                except (requests.RequestException, json.JSONDecodeError):  # not JSON?
                    # supply basic null response, although not used
                    response = {'errorDocument': {'httpMethod': None, 'httpResponseCode': None, 'message': None}}
                    if r.status_code == 200 and isinstance(r.content, bytes):  # success, although not JSON?
                        yield r.content  # e.g. PNG from op/maps/{mapId}/(image|rogueAps)
                        return
                    if r.status_code not in {400, 401, 403, 404}:  # Unknown case?
                        logErr(f"response w status_code={r.status_code} is not JSON\nresponse={r.text[:1000]}")
                self.result = r         # save for user
                if r.status_code == 200:  # OK, Success
                    pass
                elif r.status_code == 503:  # Service is up but overloaded?
                    # Yes, but will be OK in 1 sec
                    print("Server busy --" + self.diag_sleep(self.server.rateWait))
                    sys.stdout.flush()
                    continue
                elif r.status_code in {502}:  # Server Down error...
                    error_document = response['errorDocument']
                    logErr(f"{error_document['httpMethod']} returned response code "
                           + f"{error_document['httpResponseCode']}: {error_document['message']}"
                           + self.diag_str(r, f"requests.get exception for tableGet({self.tableURL}, {self.filters})")
                           + self.diag_sleep(10*60))  # ... that could possibly clear
                    continue            # try again
                elif r.status_code == 500:  # Internal Server Error. e.g. AccessPoint is disassociated
                    # CPI is buggy. ClientDetails API often returns 500 status code
                    # ***** remove this logic if Cisco fixes the bug
                    if self.tableURL.__contains__('ClientDetails'):  # ClientDetails API?
                        self.cpi_crud += 1
                        logErr(f"status_code=500 #{self.cpi_crud} from {self.tableURL} {filters}.\n"
                               + f" Retrying in 90 seconds")
                        if self.cpi_crud <= 4:
                            time.sleep(90.0)
                            continue    # try again for a different result
                    raise ConnectionAbortedError(r.status_code)  # allow try/except to handle w/o printing
                elif r.status_code == 400:  # returns html page for human
                    logErr(f"status_code={r.status_code}: Access to {self.tableURL} is Bad Request")
                    print(r.url)
                    print(r.text[:2000], flush=True)
                    raise ConnectionRefusedError(r.status_code)
                elif r.status_code == 401:  # returns html page for human
                    logErr(f"status_code={r.status_code}: Access to {self.tableURL} {filters}",
                           f"by username={self.server.username} is Unauthorized")
                    # Sadly, when the user has too many sessions open,
                    # E.g not yet timed out, CPI refuses an existing session's request
                    # with 401 Unauthorized. Try to recover at this lower level by
                    # hoping that a single 401 is too many sessions open, and that
                    # one will time-out in a few minutes.  Raise an
                    # Exception only with multiple consecutive 401 on this Reader.
                    self.four_oh_one += 1
                    if self.four_oh_one > 3:  # too many consecutive 401 Unauthorized?
                        raise ConnectionError(r.status_code)
                    else:           # patiently wait for other session(s) to close
                        time.sleep(5*60)
                        continue            # and try again
                elif r.status_code == 403:  # returns html page for human
                    logErr(f"status_code={r.status_code}: Access to {self.tableURL} is Forbidden")
                    raise ConnectionError(r.status_code)
                elif r.status_code == 404:  # returns empty html
                    logErr(f"status_code={r.status_code} {self.tableURL} Not Found")
                    raise ConnectionError(r.status_code)
                else:                   # other error
                    error_document = response['errorDocument']
                    logErr(f"status_code={r.status_code}\nresponse text={r.text[:1000]}"
                           + f"{error_document['httpMethod']} returned response code "
                           + f"{error_document['httpResponseCode']}: {error_document['message']}")
                    raise ConnectionError(r.status_code)

                ''' The GET response typically has the following forms:
{"queryResponse":
    {"@last":"mm", "@first":"nn", '@count': 'nnnn', '@type': ClientCounts', '@responseType': 'listEntityInstances',
    ... , "entity":[
        {@dtoType":ClientCountsDTO", ..., "clientCountsDTO":
            {"@displayName":"12345678901", "@id":"12345678901", "attr1":"val1", "attr2":"val2", ..., }}
        {@dtoType":ClientCountsDTO", ..., "clientCountsDTO":
            {"@displayName":"12345678901", "@id":"12345678901", "attr1":"val1", "attr2":"val2", ..., }}
        ...
        {@dtoType":ClientCountsDTO", ..., "clientCountsDTO":
            {"@displayName":"12345678901", "@id":"12345678901", "attr1":"val1", "attr2":"val2", ..., }}
    ]}}
{'mgmtResponse':
    {'@responseType': 'operation', ..., 'xxxList': {'xxxTypes': {'xxxType': [
                        {'deviceName': 'Autonomous AP', 'fullPathName': 'Autonomous AP'}
                '''
                # successful GET resets counters for consecutive errors
                self.errorSeconds = 0   # Consecutive error-seconds
                self.four_oh_one = 0    # Consecutive 401 Unauthorized status_code
                self.cpi_crud = 0       # Consecutive crud in CPI *****
                self.backoff = 1     # successful GET also resets sleep time scale
                if self.tableURL.__contains__('ClientSessions'):  # *****
                    print(f"len(response)={len(response)}")
                    print(pprint.pformat(response.get('queryResponse', response))[:4000])
                mgmt_type = self.tableURL.rpartition('/')[2][:-1]  # the type of a mgmt entry
                if not isinstance(response, dict):
                    logErr(self.diag_str(r, f"type(response)={type(response)} is not a dict"))
                    raise TypeError
                if len(response) != 1:
                    logErr(self.diag_str(r, f"len(response)={len(response)}"))
                    raise TypeError
                response_name, item = response.popitem()
                if response_name == 'queryResponse' and item.get('@responseType', None) == 'getEntity' \
                        and item.get('@type', None) is not None:
                    # A DTO response for http:/.../data/<entity-type>/<entity-id>
                    # This response form should never be seen,
                    # since query doesn't request a single <entity-id>
                    # However, starting w/release of v4, all versions changed
                    # to use this response for no results
                    logErr(self.diag_str(r, f"Received a getEntity responseType"))
                    return
                # raise TypeError ***** (?)
                elif response_name == 'queryResponse' and item.get('@responseType', None) == 'listEntityInstances' \
                        and item.get('@type', None) is not None:
                    # a DTO response for http:/.../data/<entity-type>?.full=true
                    if 'entity' not in item:
                        return          # no 'entity' indicates EOF
                    entity_list = item['entity']
                    # entityAccessor = item['@type'] + 'DTO'
                    ''' prior to release 3.x, item contained '@first' and '@last'
                    if '@first' in item and '@last' in item:
                        paging = True
                        printIf(self.verbose, f"@first={item['@first']} @last={item['@last']}")
                    else:
                        paging = False
                    '''
                    if self.recCnt < 2001 and self.tableURL.__contains__('ClientSessions'):  # *****
                        print(f"len(entity_list)={len(entity_list)}, dto_names={self.dto_names}")
                    if len(entity_list) == 0:  # No [more] records?
                        return
                    if len(self.dto_names) == 0:  # need to initialize dto_names?
                        typ = item.get('@type')  # API name
                        self.dto_names.append(typ[0:1].lower() + typ[1:] + 'DTO')
                        self.dto_names.append(typ[0:2].lower() + typ[2:] + 'DTO')
                    for row in entity_list:  # for each retrieved record ...
                        self.recCnt += 1
                        try:
                            x = row[self.dto_names[0]]
                        except KeyError:
                            try:
                                self.dto_names.append(self.dto_names.pop(0))  # rotate the guesses
                                x = row[self.dto_names[0]]
                            except KeyError:
                                keys = ', '.join(xx for xx in row)
                                print(f"Couldn't find {self.dto_names[0]} in [{keys}]")  # *****
                                logErr(self.diag_str(r, f"Couldn't find {self.dto_names[0]} in [{keys}]"))
                                return
                        if self.recCnt < 10 and self.tableURL.__contains__('ClientSessions'):  # *****
                            print(f"yielding {self.recCnt} ", end='')
                        yield x
                        if self.recCnt < 10 and self.tableURL.__contains__('ClientSessions'):  # *****
                            print(f"continuing ", end='' if self.recCnt%10 else '\n')
                    if self.tableURL.__contains__('ClientSessions'):  # *****
                        print(f"exited for after {self.recCnt} records")
                    if not self.paged:  # the API does not support paging?
                        if self.tableURL.__contains__('ClientSessions'):  # *****
                            print(f"doesn't support paging")
                        return          # Every record was returned in the first response
                elif response_name == 'mgmtResponse' and item.get('@responseType', None) == 'operation' \
                        and mgmt_type + 's' in item.get(mgmt_type + 'List', dict()) \
                        and mgmt_type in item[mgmt_type + 'List'][mgmt_type + 's']:
                    # a management operation response observed when running 3.1
                    entity_list = item[mgmt_type + 'List'][mgmt_type + 's'][mgmt_type]
                    if len(entity_list) == 0:  # No [more] records?
                        return
                    for row in entity_list:  # for each retrieved record ...
                        self.recCnt += 1
                        yield row
                    # This API does not support paging
                    return              # Every record was returned in the first response
                elif response_name == 'mgmtResponse' and item.get('@responseType', None) == 'operation':
                    # the documented management operation response
                    for key in item:    # find the entry for the response array
                        if key[0] != "@":
                            entity_list = item[key]
                            break       # found it
                    else:  # couldn't find the DTO
                        # This response structure is not recognized
                        logErr(self.diag_str(r,
                            f"Unknown response for {response_name} w/ @responseType={item.get('@responseType', None)}")
                               + f"\nitem={str(item)[:2000]}")
                        raise TypeError
                    if len(entity_list) == 0:  # No [more] records?
                        return
                    for row in entity_list:  # for each retrieved record ...
                        self.recCnt += 1
                        yield row
                    # This API does not support paging
                    return  # Every record was returned in the first response
                else:
                    # This response structure is not recognized
                    logErr(self.diag_str(r,
                        f"Unknown response for {response_name} with @responseType={item.get('@responseType', None)}")
                           + f"\nitem={str(item)[:2000]}")
                    raise TypeError
        # fall-through and return when all pages have been processed

        def defaultPager(self, param: Union[str, dict] = 'filter') -> Union[dict, str]:
            """Default paging manager.

            Pages by .firstResult={recCnt}
            The returned filter will GET all rows of a static CPI API that is
            "paged". A more sophisticated pager is required for predictable
            retrieval of rows of a table in which CPI's asynchronous updates
            cause the selected set to change during the poll, other than pure
            addition of rows at the end.

            :param param:   'filter' to return a filter
            :return:    filter if param=='filter' else None
            """
            if param == 'filter':
                return {'.firstResult': self.recCnt}

        def diag_str(self, r: Union[requests.Response, None], msg: str = '') -> str:
            """Format diagnostic details of a Requests Response.

            :param r:       the Response returned from requests.*
            :param msg:     diagnostic message
            :return:        formatted diagnostic details
            """
            s = '' if msg == '' else msg + '\n'
            if r is None:               # Was there a response from requests?
                s += self.server.baseURL + self.tableURL + ' '  # No, append URL
            else:                       # Yes, append response fields
                s += f"url={r.url}\nStatus_code={r.status_code}\n"
                s += f"headers={str(r.headers)}"
                try:
                    s += f"json={str(r.json())[:2000]}"
                except json.decoder.JSONDecodeError:
                    text = getattr(r, 'text', None)
                    s += f"text={text[:2000]}"
            return s

        def diag_sleep(self, seconds: int) -> str:
            """Sleep ``backoff*seconds``, where ``backoff *=2`` for each consecutive error.

            :param seconds:     seconds to sleep
            :return:            f"Slept {seconds} seconds"
            :raises ConnectionError if total consecutive error sleep time > max_timeout.
            """
            if self.errorSeconds > Cpi.max_timeout:  # >hour of sleeping w/o success?
                raise ConnectionError   # Yes, give up
            if self.errorSeconds > 0 and self.backoff < 16:  # Consecutive error without success?
                self.backoff *= 2    # Sleep yet twice longer
            if seconds > 0:
                seconds *= self.backoff  # scaled for consecutive errors
                self.errorSeconds += seconds  # consecutive seconds in error
                self.sleepingSeconds += seconds  # Total time sleeping
                time.sleep(seconds)     # sleep
                return f"Slept {seconds} seconds"
            return ''


class Cache:
    """
    Manage a cache, in ~/cache directory, of API contents recently read from CPI
    by the current user.
    """
    cache_dir = os.path.join(os.path.expanduser('~'), 'cache')
    cache_semaphore = threading.Semaphore()

    @classmethod
    def clear(cls):
        """Clear the cache
        """
        for fn in os.listdir(Cache.cache_dir):
            os.remove(os.path.join(Cache.cache_dir, fn))

    @classmethod
    def Reader(cls, cpi: Cpi, tbl: Union['Table', str], verbose: int = 0,
               age: float = 5.0, **kwargs) -> Generator:
        """Reads ``tbl`` from the cache if data exists  and < ``age`` days old.
        Otherwise reads from ``cpi``, while saving to cache iff all records were read.

        :param cpi:     Cisco Prime Infrastructure server instance
        :param tbl:     Table, or URL string for Cpi.Reader
        :param verbose: diagnostic message level
        :param age:     acceptable age in days
        :param kwargs:  optional key-word parameters to pass to tbl.generator
        :return:        Cache._reader_ or Cache._cacher_
        """
        if isinstance(tbl, str):        # simple URL string?
            fn = tbl.replace('/', '_').replace('\\', '_')  # map slashes to underscores
        else:                           # assume a Table
            fn = f"{tbl.version}_{tbl.prefix.replace('/', '_')}_{tbl.tableName}"
        base = os.path.join(Cache.cache_dir, fn)  # base file_name in cache
        try:
            stat = os.stat(base + '.json')
            if stat.st_mtime > time.time() - age*24*60*60:
                return Cache._reader_(base + '.json')
        except FileNotFoundError:
            with cls.cache_semaphore:   # need atomic (isdir and mkdir)
                if not os.path.isdir(Cache.cache_dir):
                    logErr(f"Cache.Reader cache directory missing. Creating '{Cache.cache_dir}'.")
                    os.mkdir(Cache.cache_dir)
        return Cache._cacher_(cpi, tbl, base, verbose, **kwargs)

    @classmethod
    def _reader_(cls, fn) -> Generator:
        """

        :param fn:  file pathname (in cache) of JSON records to read
        :return:    Generator to read from the cache
        """
        with open(fn, 'rt') as in_file:
            for line in in_file:
                yield json.loads(line)

    @classmethod
    def _cacher_(cls, cpi: Cpi, tbl: Union['Table', str], base: str,
                 verbose: int = 0, **kwargs) -> Generator:
        """Read table ``tbl`` from ``cpi``, yielding each record while writing to
        cache. Incorporates data into the cache iff all records were yielded.

        :param cpi:     Cisco Prime Infrastructure server instance
        :param tbl:     Table, or URL string for Cpi.Reader
        :param base:    base filename in the cache
        :param verbose: diagnostic message level
        :param kwargs:  optional key-word parameters to pass to tbl.generator
        :return:        Generator yields dict
        """
        with open(base + '.tmp', 'wt') as out_file:
            if isinstance(tbl, str):    # simple string URL?
                reader = Cpi.Reader(cpi, tbl, verbose=verbose)  # Yes. Simply read the URL
            else:                       # More complex table with generator
                reader = tbl.generator(cpi, tbl, verbose=verbose, **kwargs)
            for rec in reader:
                out_file.write(json.dumps(rec))
                out_file.write('\n')
                yield rec
            # if/when input is successfully exhausted
            out_file.close()            # close and rename .tmp to permanent .json
            try:
                os.remove(base + '.json')
            except OSError:
                pass
            os.rename(base + '.tmp', base + '.json')

    @classmethod
    def expire(cls, age: float, kilobytes: int) -> str:
        """Remove from the cache: each tmp file, each data file > ``age`` days old,
        and additional files by descending age, as necessary, to reduce total
        cache storage to ``kilobytes`` KB.

        Returns a summary of expired and resulting storage use

        :param age:         delete files older than age days
        :param kilobytes:   maximum allowed cache storage
        :return:            summary of storage deleted and remaining
        """
        bytes_deleted = 0
        bytes_remaining = 0
        files_deleted = 0
        files_remaining = 0
        files: list = []            # [(mtime, size, pathname), ...]
        # delete .tmp files and other files older than age days
        for entry in os.scandir(Cache.cache_dir):
            entry: os.DirEntry
            if entry.is_dir():
                continue                # ignore sub-directories
            fn = entry.name
            stat = entry.stat(follow_symlinks=False)
            size = stat.st_size         # file size in bytes
            if fn[-4:] == ".tmp":
                try:                    # try to delete because it is a .tmp
                    os.remove(os.path.join(Cache.cache_dir, fn))
                    files_deleted += 1
                    bytes_deleted += size
                except FileNotFoundError:  # file disappeared!
                    pass                # as if it were never there
                except OSError:         # Could not delete
                    files_remaining += 1
                    bytes_remaining += size
            elif stat.st_mtime < time.time() + 24*60*60*age:
                try:                    # file is older than age. Delete it.
                    os.remove(os.path.join(Cache.cache_dir, fn))
                    files_deleted += 1
                    bytes_deleted += size
                except FileNotFoundError:   # file disappeared!
                    pass                # as if it were never there
                except OSError:         # Failure. E.g permissions or in use
                    # record, but adding as a candidate is probably fruitless
                    files_remaining += 1
                    bytes_remaining += size
            else:                       # not .tmp and not too old
                # add to list as a candidate for deletion based on age
                files.append((stat.st_mtime, size, fn))
                files_remaining += 1
                bytes_remaining += size
        files.sort()                    # sort ascending by mtime, size, pathname
        # Delete additional files, as necessary, to reduce storage to < kilobytes
        while len(files) > 0 and bytes_remaining > 1000*kilobytes:
            mtime, size, fn = files.pop(0)
            # Assume that the file is successfully deleted
            files_remaining -= 1
            bytes_remaining -= size
            try:
                os.remove(os.path.join(Cache.cache_dir, fn))
                files_deleted += 1      # successfully deleted too
                bytes_deleted += size
            except FileNotFoundError:   # not successfully deleted
                pass                    # as if it were never there
            except OSError:
                files_remaining += 1    # file still remains, but not deleted
                bytes_remaining += size
        # construct summary status
        s = f"{files_deleted} files totaling {bytes_deleted:,} bytes deleted" \
            + f"{files_remaining} files totaling {bytes_remaining:,} bytes in cache"
        return s


if __name__ == '__main__':  # test with optional command argument: tableURL
    import os
    import sys
    print(f"Python {sys.version}")
    if 'PYTHONPATH' in os.environ:
        print(f"PYTHONPATH={os.environ['PYTHONPATH']}")
    print('path=\n' + '\n'.join(sys.path))
    from sys import argv, exit
    print("must be connected to case.edu network to run this test")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    server = 'ncs01.case.edu'
    if len(argv) < 1:
        print('arguments are: [relative URL of table to read]. E.g. v4/data/AccessPointDetails')
        exit(1)
    try:
        cred = credentials(server)
    except KeyError:
        print(f"No credentials found for server {server}")
        exit(1)
    myCpi = Cpi(cred[0], cred[1])

    if len(argv) > 1:
        tableURL = argv[1]              # relative URL of table
    else:
        # tableURL = 'v1/op/cliTemplateConfiguration/deviceTypes'
        tableURL = 'v4/op/maps/8197498/image'
    print(f"Testing reading the {tableURL} API")
    reader = Cpi.Reader(myCpi, tableURL, paged=True, verbose=1)
    pp = pprint.PrettyPrinter(indent=2, width=160)
    record_num = 0
    max_len = 0
    for record in reader:
        if not isinstance(record, dict):
            print(f"type of response is {type(record)}")
            if isinstance(record, bytes):
                print(f"writing length={len(record)} bytes to cpiapi.png")
                with open('cpiapi.png', 'wb') as result:
                    result.write(record)
            continue
        if record_num < 5:
            pp.pprint(record)
        record_num += 1
        max_len = max(max_len, len(record))
        if record_num > 10000:
            break
    if record_num >= 10:
        print('...')
    if record_num > 10000:
        print(f"retrieval stopped after {record_num} records")
    print(f"returned {record_num} rows with up to {max_len} attr:val pairs")
    print(f"reader.recCnt={reader.recCnt}")
    if len(argv) > 1:
        print(f"testing reading {tableURL} while updating the cache")
        start_time = time.time()
        reader = Cache.Reader(myCpi, tableURL, 0)
        record_num = 0
        for rec in reader:
            record_num += 1
        print(f"read {record_num} records in {time.time()-start_time:0.2f} seconds")

        print(f"testing reading {tableURL} from existing cache entry")
        start_time = time.time()
        reader = Cache.Reader(myCpi, tableURL, 1)
        record_num = 0
        for rec in reader:
            record_num += 1
        print(f"read {record_num} records in {time.time()-start_time:0.2f} seconds")
