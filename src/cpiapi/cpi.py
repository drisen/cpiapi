#! /usr/bin/python3
# cpi.py library Copyright 2019 by Dennis Risen, Case Western Reserve University
#
"""
Cpi class reads CPI APIs
Cache class manages a json file cache of recently read CPI API responses
"""

# requires urllib3[secure]
# obtain and install certificate for ncs01.case.edu
#

from collections.abc import Generator
from typing import Union
import json
import requests
import os
import sys
import time
import urllib3

# direct threading is Panda3d incompatible alternative for threading
# if 'direct.stdpy.threading' in sys.modules:
#     import direct.stdpy.threading as threading
# else:
import threading

from credentials import credentials
try:
    from .cpitime import logErr         # assume within import of cpiapi package
except (ModuleNotFoundError, ImportError):
    from cpitime import logErr          # __main__ or package testing


""" TODO
Unless the __init__ supplies a semaphore, attempts to create another Cpi with same
server and user as an existing instance will return the existing instance.
I.e. use constructor or metaclass=Unique
obtain and install certificate for ncs01.case.edu
"""


# import certifi  # fix certificate handling later *****


class Cpi:
    """A Cisco Prime Infrastructure server instance."""
    # Populate inheritable attributes with Cisco defaults
    rateWait = 1                    # seconds to wait to clear service busy
    maxResults = 1000               # maximum number of results per GET
    TIMEOUT = 80.0                  # seconds to wait between packets
    # 30 seconds is occasionally insufficient for, e.g. HistoricalRfLoadStats
    timeDelta = 0.0             # my epochSeconds === server's epochSeconds+timeDelta
    POSTING_DELTA = 6*60.0          # records posted within 6 minutes of event
    # rate limiting attributes
    segmentSize = .100              # seconds per window segment
    windowSize = 1.000              # seconds in CPI rate-limiting window
    perUserThreshold = 5            # Max # of user requests allowed per window
    maxConcurrent = 5               # Number of concurrent GETs allowed
    max_timeout = 3600              # Max seconds of retrying before ConnectionError

    def __init__(self, username: str, password: str,
                 baseURL: str = "https://ncs01.case.edu/webacs/api/",
                 semaphore: threading.Semaphore = None):
        """Initialize a CPI server instance with username, password, and server base URL.
        Parameters:
            username (str):			username to use on the designated server
            password (str):			password
            baseURL (str):			https URL of the api base on the server
            semaphore (threading.Semaphore):	Use this semaphore, rather than internal, for each GET
        """
        self.username = username
        self.password = password
        self.baseURL = baseURL          # URL of the server APIs
        self.history = []               # epochSeconds of each recent request to CPI
        self.semaphore = threading.Semaphore() if semaphore is None else semaphore  # for multi-thread locking
        self.rate_semaphore = threading.Semaphore(self.maxConcurrent)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # ***** until certificates are installed

    def rateLimit(self):
        """Sleep as necessary to limit requests per windowSize in msec."""
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
        """Sets default seconds offset < my epochSeconds - server's epochSeconds."""
        self.timeDelta = delta
        return self

    class Reader:
        def __init__(self, server: 'Cpi', tableURL: str, filters: dict = None,
                     verbose: int = 0, pager: callable = None, paged: bool = True):
            """Initialize to GET all records in a table.
            Parameters:
                server (Cpi):		a Cisco Prime Infrastructure instance
                tableURL (str):		API URL relative to baseURL
                filters	(dict):		additional filtering to apply in the URL
                verbose (int):		to print additional information
                pager (function):	pager() returns a filter dict
                paged (bool):		True if the table API implements paging

            """
            self.tableURL = tableURL
            self.filters = {} if filters is None else filters
            self.server = server
            self.verbose = verbose
            if pager is None:
                self.pager = self.defaultPager
            else:
                self.pager = pager
            self.paged = paged          # whether the API supports paging
            self.recCnt = 0             # number of records retrieved so far
            self.pager('init')          # initialize pager
            self.dto_names = []         # list of guesses for the DTO name
            self.four_oh_one = 0        # number of consecutive 401 unauthorized

        def __iter__(self):  # the iterator. 1st next() starts it
            """Parse through (possibly paged) GET(s) yielding one record at a time.

            Returns: with self.result = requests.get(...)
                dict: attribute:value pairs

            """
            self.sleepScale = 1     # Each consecutive errors will adjust sleep by 2x
            self.sleepingSeconds = 0    # Total seconds spent sleeping
            self.errorSeconds = 0       # Consecutive seconds of sleep from errors
            self.recCnt = 0             # number of records retrieved so far
            self.four_oh_one = 0        # no consecutive 401 Unauthorized Exceptions
            while True:  # for each page or record until EOF
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
                    print(f"  filters={filters}")
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

                # Doc. states that any error response is coded as requested
                # However, codes 401, 403, and 404 and 403 return html for human
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
                    print(self.diag_sleep(self.server.rateWait))  # ... will be OK in 1 sec
                    continue
                elif r.status_code in {502}:  # Server Down error...
                    error_document = response['errorDocument']
                    logErr(f"{error_document['httpMethod']} returned response code "
                           + f"{error_document['httpResponseCode']}: {error_document['message']}"
                           + self.diag_str(r, f"requests.get exception for tableGet({self.tableURL}, {self.filters})")
                           + self.diag_sleep(10*60))  # ... that could possibly clear
                    continue            # try again
                elif r.status_code == 500:  # Internal Server Error. e.g. AccessPoint is disassociated
                    raise ConnectionAbortedError(r.status_code)  # allow try/except to handle w/o printing
                elif r.status_code == 400:  # returns html page for human
                    logErr(f"status_code={r.status_code}: Access to {self.tableURL} is Bad Request")
                    print(r.url)
                    print(r.text[:2000])
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
                self.sleepScale = 1     # successful GET resets sleep time scale
                self.errorSeconds = 0   # and consecutive error-seconds
                self.four_oh_one = 0    # and consecutive 401 Unauthorized

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
                                logErr(self.diag_str(r, f"Unknown DTO type"))
                                return
                        yield x
                    if not self.paged:  # the API does not support paging?
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
                            f"Unknown response for {response_name} with @responseType={item.get('@responseType', None)}")
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

        def defaultPager(self, param):
            """Calculate paging filter(s).
            Cpi.Reader.__init__ calls pager('init') for any initialization
            Cpi.Reader.__iter__ calls pager('filter') before issuing each GET
            The returned filters will get all rows of a static CPI API that is
            "paged". A more sophisticated pager is required for predictable
            retrieval of rows of a table in which CPI's asynchronous updates
            cause the selected set to change during the poll, other than pure
            addition of rows at the end.

            Parameters:
                param (str):	'init' to initialize; 'filter' to return filter
            """
            if param == 'filter':
                return {'.firstResult': self.recCnt}

        def diag_str(self, r, msg: str = '') -> str:
            """Print diagnostic details of a Requests Response, then sleeps seconds.
            If error persists for >1 hour, raise ConnectionError.

            Parameters:
                r (Response):	the Response returned from requests.*
                msg (str):		message

            Returns:
                accumulated str of diagnostics
            """
            s = '' if msg == '' else msg + '\n'
            if r is None:               # Is there a response from requests?
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
            """Sleep. Update [sleep|error]Seconds. Raise error if >hour."""
            if self.errorSeconds > Cpi.max_timeout:  # >hour of sleeping w/o success?
                raise ConnectionError   # Yes, give up
            if self.errorSeconds > 0 and self.sleepScale < 16:  # Consecutive error without success?
                self.sleepScale *= 2    # Sleep yet twice longer
            if seconds > 0:
                seconds *= self.sleepScale  # scaled for consecutive errors
                self.errorSeconds += seconds  # consecutive seconds in error
                self.sleepingSeconds += seconds  # Total time sleeping
                time.sleep(seconds)     # sleep
                return f"Slept {seconds} seconds"
            return ''


class Cache:
    """
    A cache of API contents recently read from CPI by the current user.
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
               age: float = 5.0, *kwargs) -> Generator:
        """Reads tbl from cache if it exists < age days old.
        Otherwise reads from cpi, while saving to cache iff all records were read.

        Args:
            cpi: 	Cisco Prime Infrastructure server instance
            tbl: 	Table, or URL string for Cpi.Reader
            verbose: diagnostic message level
            age:	acceptable age in days
            kwargs: optional parameters to pass to tbl.generator

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
        except FileNotFoundError as e:
            with cls.cache_semaphore:   # need atomic (isdir and mkdir)
                if not os.path.isdir(Cache.cache_dir):
                    logErr(f"Cache.Reader cache directory missing. Creating '{Cache.cache_dir}'.")
                    os.mkdir(Cache.cache_dir)
        return Cache._cacher_(cpi, tbl, base, verbose, kwargs)

    @classmethod
    def _reader_(cls, fn) -> Generator:
        """

        Args:
            fn: 	file (in cache) of JSON records to read

        Returns:	Generator

        """
        with open(fn, 'rt') as in_file:
            for line in in_file:
                yield json.loads(line)

    @classmethod
    def _cacher_(cls, cpi: Cpi, tbl: Union['Table', str], base: str,
                 verbose: int = 0, *kwargs) -> Generator:
        """Read table 'tbl' from cpi, yielding each record while writing to cache.
        Incorporates into the cache iff all records were yielded.

        Args:
            cpi: 	Cisco Prime Infrastructure server instance
            tbl: 	Table, or URL string for Cpi.Reader
            base: 	base filename in the cache
            verbose:  diagnostic message level
            kwargs: optional parameters to pass to tbl.generator

        Returns:

        """
        with open(base + '.tmp', 'wt') as out_file:
            if isinstance(tbl, str):    # simple string URL?
                reader = Cpi.Reader(cpi, tbl, verbose=verbose)  # Yes. Simply read the URL
            else:                       # More complex table with generator
                reader = tbl.generator(cpi, tbl, verbose=verbose, kwargs=kwargs)
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


if __name__ == '__main__':  # test with optional command argument: tableURL
    from sys import argv, exit
    import pprint
    print("must be connected to case.edu network to run this test")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    server = 'ncs01.case.edu'
    if len(argv) < 1:
        print('arguments are: [relative URL of table to read]. E.g. v4/data/AccessPointDetails')
        exit(1)
    try:
        cred = credentials.credentials(server)
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
