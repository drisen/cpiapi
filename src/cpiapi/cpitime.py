#
# cpitime.py Copyright (C) 2019 Dennis Risen, Case Western Reserve University
# refactored from mylib.py

import calendar
from datetime import datetime
import os
import platform
from pytz import timezone
import re
import sys
import time
home_zone = timezone('US/Eastern')		# All str date input/output in this timezone


def anyToSecs(t, offset: float = 0.0) -> float:
    """Convert milliseconds:int, seconds:float, or ISO datetime:str to seconds:float.
    Parameters:
        t (object):			epoch milliseconds:int, epoch seconds:float, or ISO datetime:str
        offset (float):		epoch_msecs/1000 + offset = epoch_seconds
    Returns:
        (float):			epoch seconds
    """
    if isinstance(t, int):				# epochMillis: int msec?
        return t/1000.0 + offset		# Yes.
    elif isinstance(t, float):			# epochSeconds: float time.time()?
        return t						# no conversion necessary
    elif isinstance(t, str):			# ISO text datetime?
        return strpSecs(t)
    else:
        raise TypeError


def fromTimeStamp(t: float) -> datetime:
    """datetime.datetime(t) with home time zone"""
    return datetime.fromtimestamp(t, home_zone)


if platform.system() == 'Linux': 		# Running on Linux platform?
    import getpass
    import socket
    import subprocess

    def logErr(*s, start: str = '\n', end: str = '', **kwargs):
        print(f"{start}{strfTime(time.time())} ERROR", *s, end=end, **kwargs)
        message = ' '.join(str(x) for x in s)  # join the parameters, like print
        try:
            params = [r'/usr/bin/mailx', '-s', logErr.logSubject]+logErr.logToAddr
            subprocess.run(params,
                check=True, input=message.encode())
        except subprocess.CalledProcessError as e:
            print(f"mailx failed: {e}")
    # Default Subject of logError() email messages
    logErr.logSubject = os.path.basename(sys.argv[1]
        if re.search('python', sys.argv[0]) else sys.argv[0])
    # Default list of addressees to receive logError() messages
    logErr.logToAddr = [getpass.getuser() + '@'
        + '.'.join(socket.getfqdn().split('.')[-2:])]
else:									# No, just print

    def logErr(*s, start: str = '\n', end: str = '', **kwargs):
        params = [r'/usr/bin/mailx', '-s', logErr.logSubject] + logErr.logToAddr
        print(f"unix would call subprocess({params}, check=True, input=message=<see below>)")
        print(f"{start}{strfTime(time.time())} ERROR", *s, end=end, **kwargs)
    # Default Subject of logError() email messages
    logErr.logSubject = os.path.basename(sys.argv[1]
        if re.search('python', sys.argv[0]) else sys.argv[0])
    # Default list of addressees to receive logError() messages
    logErr.logToAddr = ["default"]


def millisToSecs(millis: int, time_delta: float = 0) -> float:
    """Convert CPI server's epochMillis:int to my time.time() equivalent"""
    return millis / 1000.0 + time_delta


def printIf(verbose: int, *s, start: str = '\n', end: str = '', **kwargs):
    if verbose > 0:
        print(f"{start}{strfTime(time.time())}", *s, end=end, **kwargs)


def strfTime(t: object, fmt: str = '%Y-%m-%dT%H:%M:%S', millis: bool = False) -> str:
    """Format epochMillis:int or epochSeconds:float to home timezone. Pass through str

    Parameters:
        t:		epoch milliseconds: int, epoch seconds: float, or date str
        fmt:	strftime format string. Default='%Y-%m-%dT%H:%M:%S'
        millis:	True to include 3-digit milliseconds
    Returns:
        (str):	home time zone time string
    """
    try:
        if isinstance(t, float):		# epoch seconds from time.time()?
            dt = datetime.fromtimestamp(t, home_zone)
        elif isinstance(t, int):		# epoch msec from server
            dt = datetime.fromtimestamp(millisToSecs(t), home_zone)
        elif isinstance(t, str):
            try:
                secs = strpSecs(t)		# try to convert to UTC seconds
                dt = datetime.fromtimestamp(secs, home_zone)
            except ValueError:			# No. Unsuccessful
                return t				# just return the string
        else:
            return str(t)
        s = dt.strftime(fmt)
        if millis:						# output milliseconds too?
            return s + f"{dt.microsecond/1000000.0:.3f}"[-4:]
        else:
            return s
    except OSError:						# fromtimestamp didn't like argument
        return str(t)


def strpSecs(s: str) -> float:
    """Parse ISO-like datetime text to UTC epochSecond

    Recognizes 'Z' Zulu zone as 0000. About 6x faster than dateutil.parser
    :param s:   ISO datetime text
    :return:    float epoch seconds
    """
    m = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.[0-9]+)(.*)', s)
    if m is not None:					# an ISO-like date?
        try:
            zone = m.group(3)
            z = re.fullmatch(r'[+-][0-9]{4}', zone)
            if zone[0] == 'Z':			# Zone is Military Zulu?
                offset = 0				# *.strptime don't understand Zulu
            elif z is not None:			# Zone is +/-HHMM:
                offset = (-60 if zone[0] == '+' else 60)*(int(zone[1:3])*60+int(zone[3:5]))
            else:						# not prepared to parse some other format
                raise ValueError('Zone not military or Zulu')
            # time.strptime doesn't understand zones or fractional seconds
            secs = calendar.timegm(time.strptime(m.group(1), '%Y-%m-%dT%H:%M:%S'))
            if len(m.group(2)) > 0:		# optional fractional seconds?
                secs += float(m.group(2)) 	# Yes. works for any number of digits
            return secs+offset
        except ValueError:				# can't think of any specific error
            raise ValueError
    raise ValueError('s does not match ISO format')


def strpTime(date_string: str, fmt: str) -> float:
    """datetime.strptime localized from home time zone"""
    return home_zone.localize(datetime.strptime(date_string, fmt)).timestamp()


def secsToMillis(t: float, time_delta: float = 0.0) -> int:
    """Convert my time.time():float to CPI server's epochMillis:int."""
    if not isinstance(t, float):
        raise ValueError
    return int((t - time_delta) * 1000.0)


def verbose_1(verbose: int):
    """Return verbosity level minus 1. E.g. for lower layer
    Parameter:
        verbose (int/bool)	bool or integer verbosity level
    Returns:
        bool input or verbose-1
    """
    if isinstance(verbose, bool): 		# bool
        return 1 if verbose else 0 		# convert to int
    elif isinstance(verbose, int): 		# int is decremented
        return verbose-1 if verbose > 0 else 0
    else:								# other input
        raise ValueError(f"type={type(verbose)}")
