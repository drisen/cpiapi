#!/usr/bin/python3
# cpitable.py is Copyright 2018 by Dennis Risen, Case Western Reserve University
#
"""
Defines the classes (Named, SubTable, Table, Pagers), Pager instances and
record generators for semantically consistent access to the CPI APIs
through relational table definitions.
Defines the allowable field types and known Enums

"""

from collections import defaultdict
from collections.abc import Callable, Iterable
import csv
from datetime import datetime, timedelta
import _io                      # expose the _io.TextWrapper class for hints
from math import pow
import os
import re
import sys
import time
from typing import Union

import requests

# direct threading is Panda3d incompatible alternative for threading
# if 'direct.stdpy.threading' in sys.modules:
#     import direct.stdpy.threading as threading
# else:
import threading

try:
    _path = __path__
    print(f"cpitable __path__ is {_path}")
    from .cpitime import anyToSecs, logErr, printIf, millisToSecs, secsToMillis, strfTime, verbose_1
    from .cpi import Cpi
except NameError:
    print(f"cpitable __path__ is <undefined>")
    from cpitime import anyToSecs, logErr, printIf, millisToSecs, secsToMillis, strfTime, verbose_1
    from cpi import Cpi
from loom import Queue

MINUTE = 60.0                   # seconds in a minute
HOUR = 60*MINUTE                # seconds in an hour
DAY = 24*HOUR                   # seconds in a day

new_cd = {}                     # new poll for ClientDetails
new_cs = {}                     # new poll for ClientSessions
old_cd = {}                     # previous poll for ClientDetails
old_cs = {}                     # previous poll for ClientSessions
"""TODO
"""


def a_type(name: str, input_example: object, sql_type: str, hive_type: str, hive_regex: str):
    """Add a data type to the types dict.

    Parameters:
        name (str):			type name
        input_example (object):	example of input data, for input type checking
        sql_type (str):		equivalent type name in SQL
        hive_type (str):	equivalent type name in Hive
        hive_regex (str):	Regex for parsing output field into Hive
    """
    global allTypes
    allTypes[name] = {'name': name, 'type': type(input_example),
                      'sql_type': sql_type, 'hive_type': hive_type, 'hive_regex': hive_regex,
                      'UsageCount': 0, 'values': None}  # values is None --> not an enum


# a type instance may create a private copy with a 'check':False entry


def a_enum(name: str, values: list):
    """Add an enum data type to the types dict.

    Parameters:
        name (str:)			type name
        values (list):		each allowed value
    """
    global allTypes
    global enum_regex
    v = dict()                          # dict of enum values for fast lookup
    i = 0
    for x in values:                    # of each value in the provided list
        v[x] = i                        # a value
        i += 1
    allTypes[name] = {'name': name, 'type': type('abc'), 'sql_type': 'name',
                      'hive_type': name, 'hive_regex': enum_regex, 'UsageCount': 0, 'values': v}


# a type instance may create a private copy with a 'check':False entry


enum_regex = r'(?:(?:"((?:(?:"")|[^"])*)")|([^,"]*)'
numericTypes = {'epochMillis', 'double', 'float', 'int', 'long', 'smallint'}

# Add each simple type to known types
allTypes = dict()
a_type('boolean', False, 'BOOLEAN', 'BOOLEAN', '([^,]*)')  # accepts t,y,o,1 | f,n.of,0; emits t|f
a_type('Date', '', 'TIMESTAMP WITH TIME ZONE', 'TIMESTAMP WITH TIME ZONE',
       r'([0-9T:\-\.]*)')
a_type('DateBad', '', 'TIMESTAMP WITH TIME ZONE', 'TIMESTAMP WITH TIME ZONE',
       r'([0-9T:\-\.]*)')
a_type('double', 1.0, 'DOUBLE PRECISION', 'DOUBLE PRECISION',
       r'((?:\d*\.\d*))|)')  # 8-byte floating point
a_type('epochMillis', 1536691480070, 'TIMESTAMP WITH TIME ZONE',
       'TIMESTAMP WITH TIME ZONE', r'([0-9T:\-\.]*)')
a_type('float', 1.0, 'REAL', 'REAL', r'((?:\d*\.\d*))|)')  # 4-byte floating-point
a_type('ignore', 'na', 'na', 'na', '')
a_type('inet', '129.22.123.45', 'INET', 'VARCHAR(15)',
       r'(?:(?:"((?:(?:"")|[^"])*)")|([^,"]*)')  # IPv4 or IPv6 internet address
a_type('instant', '', 'TIMESTAMP WITH TIME ZONE', 'TIMESTAMP WITH TIME ZONE',
       r'([0-9T:\-\.]*)')
a_type('int', 1, 'INTEGER', 'INTEGER', r'(\d*)')  # 4-byte signed
a_type('smallint', 1, 'SMALLINT', 'SMALLINT', r'(\d*)')  # 2-byte signed
a_type('array', list(), 'ARRAY', 'VARCHAR(5000)',
       r'(?:(?:"((?:(?:"")|[^"])*)")|([^,"]*)')
# 	PostgresSQL accepts { val1 delim val2 delim ...} with default delim=','. May be nested
a_type('long', 1, 'BIGINT', 'BIGINT', r'(\d*)')  # 8-byte signed
a_type('macaddr', 'xxxxxxxxxxxx', 'MACADDR', 'VARCHAR(12)',
       r'(?:(?:"((?:(?:"")|[^"])*)")|([^,"]*)')
# 	PostgresSQL removes [:-.] on input; outputs 'xx:xx:xx:xx:xx:xx'
a_type('String', '', 'VARCHAR', 'VARCHAR(200)',
       r'(?:(?:"((?:(?:"")|[^"])*)")|([^,"]*)')
# 	PostgresSQL allows the length to be omitted
# 	and has 'TEXT' type for unlimited length
# Add the ENUMs to known types
# The commented ENUMS are not currently used in table definitions
# enum labels are case-sensitive and include white-space. Value occupies 4-bytes
# When values are not otherwise ordered,
# values are ordered from boring to alarming, not in Cisco's internal order.
# a_enum('AccessPointTypeEnum', ['UNKNOWN', 'ENABLE', 'DISABLE'])
a_enum('AlarmSeverityEnum', ['CLEARED', 'INFORMATION', 'WARNING',
                             'MINOR', 'MAJOR', 'CRITICAL'])
a_enum('AntennaDiversityEnum', ['NOT_APPLICABLE', 'CONNECTOR_A',
                                'CONNECTOR_B', 'ENABLED'])
a_enum('AntennaModeEnum', ['OMNI', 'NOTAPPLICABLE', 'SECTOR_A', 'SECTOR_B'])
a_enum('AntennaTypeEnum', ['INTERNAL', 'NOT_APPLICABLE', 'EXTERNAL',
                           'CIRCULAR', 'LINEAR'])
a_enum('ApAdminStatusEnum', ['ENABLE', 'DISABLE', 'UNKNOWN'])
a_enum('AuthenticationAlgorithmEnum', ['OPENANDEAP', 'SHAREDKEY',
                                       'OPENSYSTEM', 'UNKNOWN'])
# used by CcxFSVersion, CcxLSVersion, CcxMSVersion, CcxVSVersion
a_enum('CcxFSVersionEnum', ['V2', 'V1', 'NONE', 'UNSUPPORTED', 'NONE'])
a_enum('CCXVersionEnum', ['V' + str(x) for x in range(6, 1-1, -1)]
       + ['UNSUPPORTED'])
a_enum('ChannelAssignmentEnum', ['AUTOMATIC', 'CUSTOM'])
a_enum('ChannelBandwidthEnum', [
    '5 MHz', '10 MHz', '20 MHz', '40 MHz', 'Below 40 MHz',
    'Above 40 MHz', '80 MHz', '160 MHz', 'NOTAPPLICABLE'])
a_enum('ChannelNumberEnum',
       ['UNKNOWN'] + ['_' + str(i)
                      for r in [(1, 14 + 1), (20, 26 + 1),
                                (34, 48 + 1, 2), (52, 64 + 1, 4), (100, 144 + 1, 4),
                                (149, 173 + 1, 4)] for i in range(*r)])
a_enum('CkipEncryptionTypeEnum', ['LEN104', 'LEN40', 'NONE'])
a_enum('CleanAirSensorStatus', ['UP', 'NOTAPPLICABLE', 'DOWN'])
# a_enum('ClientAaaOverrideAclAppliedEnum', ['YES', 'NO', 'NA'])
a_enum('ClientAclAppliedEnum', ['YES', 'NO', 'NA'])
a_enum('ClientApModeEnum',
       ['LOCAL', 'MONITOR', 'HREAP', 'ROGUEDETECTOR', 'BRIDGE', 'SECONNECT',
        'FLEXPLUSBRIDGE', 'REMOTEHYBRID', 'SENSOR', 'UNKNOWN'])
a_enum('ClientCountTypeEnum', ['DEVICE', 'ACCESSPOINT', 'MAPLOCATION',
                               'SSID', 'VIRTUALDOMAIN', 'GUEST'])
a_enum('ClientIpAddressAssignmentType', ['DHCPV6', 'SELF_ASSIGNED',
                                         'SLAAC_OR_STATIC', 'UNKNOWN'])
a_enum('ClientIpAddressScope', ['DHCPV6', 'SLAAC_OR_STATIC', 'SELF_ASSIGNED'])
a_enum('ClientIpTypeEnum', ['IPV4', 'IPV6', 'DUALSTACK', 'NOTDETECTED'])
# output data from ClientDetails has DOT11N2_4GNZ rather than DOT11N2_4GHZ
a_enum('ClientProtocolEnum',
       ['DOT11AX5GHZ', 'DOT11AX2_4GHZ', 'DOT11AC', 'DOT11N5GHZ', 'DOT11N2_4GNZ',
        'DOT11G', 'DOT3', 'DOT3GUEST', 'MOBILE', 'DOT11B', 'DOT11A',
        'UNDEFINED', 'UNKNOWN'])
a_enum('ClientSpeedEnum', ['SPEED10G', 'SPEED1G', 'SPEED100M', 'SPEED10M',
                           'UNKNOWN'])
a_enum('ClientStatusEnum',
       ['IDLE', 'AUTHPENDING', 'AUTHENTICATED', 'ASSOCIATED', 'POWERSAVE',
        'DISASSOCIATED', 'TOBEDELETED', 'PROBING', 'BLACKLISTED',
        'NOTCONFIGURED', 'UNAUTHENTICATED'])
a_enum('ConnectionTypeEnum', ['LIGHTWEIGHTWIRELESS', 'AUTONOMOUSWIRELESS', 'WIRED'])
a_enum('DeviceAdminStatusEnum', ['MANAGED', 'UNMANAGED', 'MAINTENANCE'])
a_enum('DisabledAllowedNotAllowedEnum', ['DISABLED', 'ALLOWED',
                                         'NOTALLOWED', 'XCONNECTNOTALLOW'])
a_enum('DisabledAllowedRequiredEnum', ['DISABLED', 'ALLOWED', 'REQUIRED'])
a_enum('DisabledEnabledRequiredEnum', ['DISABLED', 'ENABLED', 'REQUIRED'])
# data from ClientDetails has UNNOWN rather then UNKNOWN
a_enum('EapTypeEnum', ['PEAP', 'EAPTLS', 'TTLS', 'LEAP', 'SPEKE', 'EAPFAST',
                       'NA', 'UNNOWN', 'MD5', 'EAPSIM'])
a_enum('EncryptionCypherEnum', ['CCMPAES', 'TKIPMIC', 'LITERAL2',
                                'WEP140', 'WEP128', 'NONE', 'NA', 'UNKNOWN'])
# a_enum('GroupDeviceRuleOperationEnum', ['IS_EMPTY'
# , 'IS_NOT_EMPTY', 'IS_TRUE', 'IS_FALSE', 'CONTAINS', 'NOT_CONTAINS', 'EQUALS'
# , 'NOT_EQUALS', 'STARTS_WITH', 'ENDS_WITH', 'GREATER_THAN', 'LESS_THAN'
# , 'GREATER_EQUALS', 'LESS_EQUALS', 'IN_RANGE', 'MATCHES', 'NOT_MATCHES'])
# a_enum('GroupTypeEnum',  ['NETWORK_DEVICE', 'PORT'])
# a_enum('EventAlarmCategoryEnum', None)
a_enum('HreapAuthenticationEnum', ['YES', 'NO', 'NA'])  #
a_enum('InterfaceMappingTypeEnum', ['INTERFACE', 'INTERFACEGROUP'])  #
a_enum('InventoryCollectionStatusEnum',
       ['IN_SERVICE', 'COMPLETED', 'MAJORCOMPLETED', 'SYNCHRONIZING',
        'COLLECTIONFAILURE', 'PARTIALCOLLECTIONFAILURE', 'SNMPCONNECTIVITYFAILED',
        'WRONGCLICREDENTIALS', 'WRONGHTTPCREDENTIALS',
        'MAJORSYNCHRONIZING', 'MINORSYNCHRONIZING', 'SNMPUSERAUTHENTICATIONFAILED',
        'NOLICENSE', 'ADDINITIATED', 'DELETEINPROGRESS', 'PINGUNREACHABLE',
        'SPT_ONLY', 'IN_SERVICE_MAINTENANCE'])  #
a_enum('IPv4AddressAvailTypeEnum',
       ['PUBLIC', 'PORTRESTRICTED', 'SINGLENATPRIVATE', 'DOUBLENATPRIVATE',
        'PORTRESTRICTEDSINGLENATPRIVATE', 'PORTRESTRICTEDDOUBLENATPRIVATE',
        'UNKNOWN', 'NOTAVAILABLE'])  #
a_enum('IPv6AddressAvailTypeEnum', ['AVAILABLE', 'NOTAVAILABLE', 'UNKNOWN'])  #
a_enum('LanTypeEnum', ['WIRELESS', 'GUEST', 'REMOTE'])  #
a_enum('LifecycleStateEnum',
       ['UNKNOWN', 'ADDED_ININITIALSTATE', 'MANAGED_BUT_NEVERSYNCHRONIZED',
        'MANAGED_AND_SYNCHRONIZED', 'MANAGED_BUT_OUTOFSYNC',
        'MANAGED_BUT_LOSSOFCONNECTIVITY', 'PREPROVISIONED', 'UNMANAGED',
        'INSERVICE_MAINTENANCE', 'MANAGED_BUT_INCOMPLETE',
        'MANAGED_BUT_AGENTSHUTTINGDOWN', 'MANAGED_PREPARINGFORMAINTENANCE',
        'MANAGED_BUT_DUPLICATE', 'MANAGED_CONFLICTINGCREDENTIALS',
        'MANAGED_BUT_SYNCHRONIZING', 'UNMANAGED_UNLICENSED', 'IN_SERVICE',
        'OUT_OF_SERVICE', 'OUT_OF_SERVICE_FOR_MAINTENANCE', 'SYNC_DISABLED',
        'QUARANTINED'])  #
a_enum('LocationGroupTypeEnum', ['DEFAULT', 'CAMPUS', 'BUILDING',
                                 'FLOORAREA', 'OUTDOORAREA'])  #
# a_enum(types, ['AND', 'OR'])
a_enum('MeshRoleEnum', ['MAP', 'RAP'])  #
a_enum('MobilityStatusEnum',
       ['UNASSOCIATED', 'LOCAL', 'ANCHORED', 'FOREIGN', 'HANDOFF', 'UNKNOWN',
        'EXPORTANCHORED', 'EXPORTFOREIGN'])  #
a_enum('MonitorOnlyModeEnum', ['LOCAL', 'MONITOR', 'REAP', 'ROGUE_DETECTOR',
                               'SNIFFER', 'BRIDGE', 'SF_CONNECT', 'REMOTE_BRIDGE',
                               'REMOTE_HYBRID', 'SENSOR', 'FLEX_LOCAL'])  #
a_enum('NACStateEnum', ['ACCESS', 'NA', 'INVALID', 'QUARANTINE'])  #
a_enum('NetworkAuthTypeEnum', ['ACCEPTANCE', 'ENROLLMENT',
                               'REDIRECTION', 'DNSREDIRECTION', 'NOTCONFIGURED'])  #
a_enum('NetworkTypeEnum', ['PRIVATE', 'PRIVATEWITHGUESTACCESS', 'PUBLICPAID',
                           'PUBLICFREE', 'PERSONALDEVICE', 'EMERGENCYSERVICEONLY',
                           'TESTEQUIPMENT', 'WILDCARD', 'UNKNOWN'])  #
a_enum('Peer2PeerBlockingEnum', ['DISABLE', 'DROP', 'FORWARDUP'])  #
a_enum('PhoneSupport7920Enum', ['DISABLED', 'CLIENTCAC', 'APCAC',
                                'CLIENTANDAPCAC'])  #
a_enum('PmipMobilityTypeEnum', ['NONE', 'PMIP'])  #
a_enum('PoeStatusEnum', ['NORMAL', 'LOW', 'FIFTEENDOTFOUR', 'SIXTEENDOTEIGHT',
                         'EXTERNAL', 'TWENTYFIVEDOTFIVE', 'MIXEDMODE'])  #
a_enum('PoeStatusEnumInt', [])  # interpret values per PoeStatusEnum
a_enum('PolicyTypeStatusEnum',
       ['IDLE', 'RUNNING', 'NOMETHOD', 'AUTHENTICATIONSUCCEEDED',
        'AUTHENTICATIONFAILED', 'AUTHORIZATIONSUCCEEDED',
        'AUTHORIZATIONFAILED', 'DISASSOCIATED'])  #
a_enum('PortNoEnum', ['ICMPESP', 'FTP', 'SSH', 'HTTP', 'TTLSVPN',
                      'PPTPVPN', 'VOIP', 'IKEV2', 'IPSECNAT'])  #
a_enum('PortStatusEnum', ['CLOSED', 'OPEN', 'UNKNOWN'])  #
a_enum('PostureStatusEnum', ['COMPLIANT', 'NA',
                             'PENDING', 'UNKNOWN', 'NONCOMPLIANT', 'ERROR'])  #
a_enum('ProtocolNameEnum', ['ICMP', 'FTP', 'IKEV2', 'ESP'])  #
a_enum('PskFormatEnum', ['DEFAULT', 'HEX', 'ASCII'])  #
a_enum('QosEnum', ['BRONZE', 'SILVER', 'GOLD', 'PLATINUM'])  #
a_enum('RadioAdminStatusEnum', ['ENABLE', 'DISABLE', 'UNKNOWN'])  #
a_enum('RadioOperStatusEnum', ['UP', 'DOWN', 'NOTASSOCIATED', 'UNKNOWN'])  #
a_enum('RadioRoleEnum', ['SHUTDOWN', 'UPDOWNLINK', 'UPLINK', 'DOWNLINK', 'ACCESS',
                         'UPLINKACCESS', 'DOWNLINKACCESS', 'UPDOWNLINKACCESS',
                         'NOTAPPLICABLE'])  #
a_enum('RadioBandEnum', ['2.4 GHz', '5 GHz', 'Unknown'])  #
a_enum('RadioPolicyEnum', ['ALL', 'ONLY80211A', 'ONLY80211B', 'ONLY80211G',
                           'ONLY80211BG', 'ONLY80211AG', 'ONLY80211AB', 'NONE',
                           'REMOTELAN'])  #
a_enum('ReachabilityStateEnum',
       ['REACHABLE', 'UNKNOWN', 'UNREACHABLE', 'AGENT_UNREACHABLE', 'AGENT_UNLOADED',
        'PING_REACHABLE', 'PING_UNREACHABLE'])  #
a_enum('RealmEapAuthMethodEnum',
       ['NONEAPINNERAUTH', 'INNERAUTHEAP', 'CREDENTIAL', 'TUNNELEDEAPCREDENTIAL'])  #
a_enum('RealmEapAuthParamEnum',
       ['NONE', 'PAP', 'CHAP', 'MSCHAP', 'MSCHAPV2', 'LEAP', 'PEAP', 'EAPTLS',
        'EAPFAST', 'EAPSIM', 'EAPTTLS', 'EAPAKA', 'SIM', 'USIM', 'NFCSECURE',
        'HARDWARETOKEN', 'SOFTTOKEN', 'CERTIFICATE', 'USERNAMEPASSWORD', 'RESERVED',
        'ANONYMOUS', 'VENDORSPECIFIC'])  #
a_enum('RealmEapMethodEnum',
       ['NONE', 'LEAP', 'EAPPEAP', 'EAPTLS', 'EAPFAST', 'EAPSIM',
        'EAPTTLS', 'EAPAKA'])  #
a_enum('RFProfileEnum', ['PASSED', 'FAILED'])  #
a_enum('RxNeighborChannelWidthEnum',
       ['5 Mhz', '10MHz', '20 MHz',
        '40 MHz', 'Below 40 MHz', 'Above 40MHz', '80 MHz', '160 MHz'])  #
a_enum('SecurityPolicyEnum',
       ['DOT1X', 'WPA2VFF', 'WPA2', 'WPA1', 'NA', 'UNKNOWN', 'CCKM',
        'MACAUTHBYPASS', 'WEBAUTH', 'WPA'])  #
a_enum('SecurityPolicyStatusEnum', ['PASSED', 'FAILED'])  #
# a_enum('ThirdPartyApOperationalStatusEnum', ['REGISTERED', 'NOTREGISTERED', 'DOWNLOADING'])
a_enum('ServiceDomainTypeEnum',
       ['LOGICAL', 'CAMPUS', 'MULTI_FLOOR', 'FLOOR', 'FLOOR_AREA', 'OUTDOOR_AREA'])
a_enum('TxPowerControlEnum', ['AUTOMATIC', 'CUSTOM'])  #
a_enum('unifiedApInfo_poeStatusEnum',
       ['NORMAL', 'FIFTEENDOTFOUR', 'SIXTEENDOTEIGHT', 'LOW', 'EXTERNAL',
        'TWENTYFIVEDOTFIVE', 'MIXEDMODE'])  # 4--> 'NORMAL'
a_enum('UnifiedApTagSourceEnum', ['NONE', 'STATIC', 'FILTER',
                                  'AP', 'DEFAULT', 'LOCATION'])  #
a_enum('UnifiedRadioTypeEnum', ['802.11a', '802.11a/n', '802.11ac',
                                '802.11a/n/ac', '802.11b/g', '802.11b/g/n',
                                'Unknown', '802.11a/n/ac/ax', 'XOR (2.4GHz)',
                                'XOR (5GHz)', 'XOR (Monitor Mode)', 'BLE'])  # 3.7.1 added last 4
a_enum('WanLinkStatusEnum', ['LINKUP', 'LINKDOWN',
                             'LINKINTESTSTATE', 'NOTCONFIGURED'])  #
a_enum('WanSymLinkStatusEnum', ['SAME', 'DIFFERENT'])  #
a_enum('WebSecurityEnum', ['ENABLED', 'DISABLED'])  #
a_enum('WepStateEnum', ['NA', 'ENABLED', 'DISABLED'])  #
a_enum('WepEncryptionTypeEnum', ['WEP104', 'NONE', 'WEP40',
                                 'WEP128', 'AESOCB128', 'WEP_40', 'WEP_104'])  #
a_enum('WGBStatusEnum', ['REGULARCLIENT', 'WGBCLIENT', 'WGBAP'])  #
a_enum('WiredClientTypeEnum', ['NA', 'WIREDGUEST', 'WGB', 'EVORA'])  #
a_enum('WlanWebAuthTypeEnum', ['DEFAULT', 'CUSTOMIZED', 'EXTERNAL'])  #
a_enum('x8021EncryptionTypeEnum', ['WEP104', 'WEP40', 'WEP128',
                                   'NONE', 'WEP_40', 'WEP_104'])  #


class Named:
    """self.table_name used by Pager and SubTable"""

    def __init__(self, *args, table_name: str, **kwargs):
        """
        Args:
            table_name:	full pathname of the Table or SubTable
        """
        # print(f"Named.__init__(table_name={table_name}, kwargs={kwargs}")
        super().__init__(**kwargs)
        self.tableName: str = table_name


class Pager(Named):
    timeScale: float = 1.0          # scale hours of data to collect per batch
    catchup: float = 0.25           # multiplier for polling period when catching up
    rollup: float = DAY             # default seconds before CPI rolls-up the data

    def __init__(self, *args, polled: bool, poll_period: float, recs_per_hour: int, **kwargs):
        """Create new Pager instance.

        Parameters:
            polled (bool):		True if timestamped poll of entire table
            poll_period (float)	seconds until next poll from
                                last poll if<=1DAY else start of today
            recs_per_hour (int): estimated record qty generated per poll or hour
        """
        super().__init__(*args, **kwargs)
        self.idField = None             # No primary key, yet
        self.filterCnt: int = 0  # count of calls to filterCnt since last message printed
        self.polledTime: float = 0.0    # time.time() that this poll started
        self.timeField: Union[str, None] = None      # name of the timeField, if any
        self.timeField_type = ''        # in {'bad', 'int', 'long', 'string', ...}
        # dynamic state
        self.lastId = 0                 # maximum seen value of the primary key
        self.minSec = 0                 # time_field's filtering value
        self.maxTime = 0                # time_field's max native value
        self.nextPoll: float = 0.0      # Scheduled epochSeconds for next batch.
        self.paged: bool = True         # Assume that this API supports paging
        self.polled: bool = polled      # True if polled, else False
        self.pollPeriod: float = poll_period  # seconds to next poll from (lastPoll if<1DAY else today)
        self.prev_poll = dict()         # {primary_key: collection_time, ...}
        self.recordsPerHour: int = recs_per_hour  # est. record qty per poll or hour
        self.startPoll: float = 0.0     # epochSeconds that the poll started
        self.recCnt: int = 0            # number of records read
        self.rollup = Table.rollup      # default interval before data is rolled-up
        self.verbose: int = 0           # default is no diagnostic messages

    def batch_next_poll(self, max_time: float = None):
        """Set nextPoll after a partial poll through approx max_time:epochSeconds."""
        period = self.period()
        polled_time = self.polledTime
        if max_time is not None:        # record(s) contained a timestamp?
            if polled_time - max_time > self.rollup:  # Losing records now?
                delta = 0               # schedule immediate next poll
            elif polled_time - max_time < period:  # within a one period of completion?
                delta = Table.catchup*period  # schedule for factor*period from polled_time
            else:                       # between rollup and 1 period
                # alpha=0 at polled_time-max_time=rollup; alpha=1 at polled_time-max_time=period
                alpha = (self.rollup - (polled_time - max_time))/(self.rollup - period)
                delta = Table.catchup*period*alpha ** 3  # 2*alpha*integral[0:x](x dx)
            print(f"polled_time={strfTime(polled_time)} - max_time={strfTime(max_time)} = ",
                  f"{(polled_time - max_time)//60}minutes, period={period}, delta={delta}")
        else:                   # no timestamp guidance. Collect at 1/10 normal period
            delta = period/10
        self.nextPoll = polled_time + max(delta, MINUTE)  # be fair to other tables
        print(f"table.verbose={self.verbose}, {self.tableName}.nextPoll ",
              f"interval {int(delta/60)}minutes at {strfTime(self.nextPoll)}")

    def get_batch_size(self) -> int:
        """Return the maximum number of records in a batch."""
        if self.polled:                 # Polled table?
            return 1000000000           # essentially unlimited records
        return int(3*self.recordsPerHour*self.period()/HOUR)

    def next_poll_update(self):
        """Advance self.nextPoll per poll_period from polledTime or today."""
        p = self.pollPeriod
        period = p if p <= DAY else int(p/DAY)*DAY
        printIf(self.verbose, f"period={period}, timeScale={Table.timeScale}")
        if period <= DAY:               # poll_period is a duration<= 1 day?
            self.nextPoll = self.polledTime + period
        else:                           # poll_period is a time in a following day
            # calculation must be done in local date and time
            dt = datetime.fromtimestamp(self.polledTime)
            dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)  # local today
            offset = timedelta(days=period//DAY, seconds=period % DAY)
            self.nextPoll = (dt + offset).timestamp()  # convert back to time.time()

    def period(self) -> float:
        """Return the number of seconds between polls, scaled by timeScale."""
        p = self.pollPeriod
        return Table.timeScale*(p if p <= DAY else int(p/DAY)*DAY)

    def zero_id_field(self):
        """If key(s) are present, set lastId to lowest numeric value for field's type."""
        if self.idField is None:
            return                      # No idField has been set
        # 		if self.key_defs[0][0] in numericTypes:
        if isinstance(self.lastId, str):
            self.lastId = '0'
        else:
            self.lastId = 0

    ''' 		P A G E R   F U N C T I O N S

    '''

    def filter_talk(self, filter_msg: str):
        """If self.verbose>0, print filter_msg 1st and every Nth call."""
        if self.verbose <= 0:           # only print if verbose
            return                      # not verbose
        elif self.filterCnt <= 0:       # 1st or a Nth call to filter?
            print(filter_msg, end=' ', flush=True)
            self.filterCnt = 0          # print next filtered message
        else:
            pass
        self.filterCnt = (self.filterCnt + 1) % 5

    def cs_pager(self, param: object) -> dict:
        """Perform paging functions for reading the ClientSessions table.
Assumptions:
-	The difference between the server's and client's clocks is bounded.
    Updates to sessionEndTime appear in CPI's database within bounded time.
    The sum of the above time durations is less than Cpi.POSTING_DELTA seconds.
-	The database id, @id, of each inserted record is > the @id of all previous
    records. API delivers records ordered by database id, @id.
cs_pager('filter') keeps track of:
    lastId	the @id of the most recently read record; or 0
    maxTime	the maximum sessionEndTime of frozen records that have been read
    minSec	the minimum sessionStartTime time of record(s) that might not have
            been reported in previous sessions.
to return a filter of the form "@id>lastId and sessionEndTime>minSec" that reads
at least the sessions which were not frozen and reported in previous batches.
The first ever collection begins with lastId=0 and minSec=0, so the filter
is @id>0 and sessionEndTime>0.
When called with 'endBatch', it calls batch_next_poll(maxTime) to set the nextPoll
time appropriate to how far behind the collection is.
On resuming the collection, lastId has advanced to continue collecting more
records.
After the final record, cpiapi.Reader calls pager('complete').
cs_pager updates minSec and sets lastId = 0, so that following batches will
collect only those sessions that were active or closed after minSec.

Parameters:
    param  (object): 'init' initializes the pager before a batch of records
            'filter' returns a filter for a https:GET
            'endBatch' after a partial poll (recCnt >= self.get_batch_size())
            'complete' after reading the last record in the table
            dict: with each record, so that pager can see each record.
Returns:
    None or dict:
        """
        if isinstance(param, dict):     # called with current record
            self.lastId = param['@id']  # max(@id)
            self.maxTime = max(self.maxTime, param['sessionStartTime'])
        elif param == 'filter':         # return a filter for paging the table
            result = {'id': f"gt({param_str(self.lastId)})",
                      'sessionEndTime': f"gt({param_str(self.minSec)})"}
            self.filter_talk(f"id>{self.lastId}&sessionEndTime>{strfTime(self.minSec)}")
            return result
        elif param == 'init':           # initialize
            self.filterCnt = 0          # print next filtered message
            if self.lastId == 0:        # last poll was completed?
                self.startPoll = time.time()  # initialize start time of this poll
        elif param == 'endBatch':       # Advance nextPoll
            self.batch_next_poll(millisToSecs(self.maxTime))
        elif param == 'complete':       # Schedule nextPoll per table parameters
            self.minSec = secsToMillis(self.startPoll - 6*60.0)  # POSTING_DELTA n/a
            self.zero_id_field()        # start next collection at the beginning
            self.next_poll_update()     # schedule and lastId = 0
        else:
            logErr(f"{self.tableName} unknown pager function code {param}")
            raise TypeError

    def hist_pager(self, param: object = 1) -> dict:
        """Perform paging functions for reading a table of historical records.
Records are read in @id order, which corresponds closely to time_field order.
Each batch advances the lastId to the maximum (i.e. last) @id read.
Assumptions:
-	The database id, @id, of each inserted record is > the @id of all previous
    records. API delivers records ordered by database id, @id.
-	The table has an id_field, which if not @id orders the records exactly as @id
-	if table is defined to have a time_field, the pager uses it to escalate
    polling for older records. The time_field in each record records
    the approximate time that the record was inserted into the database.
    Few records are missing a time_field value.

Parameters:
param  'init' initializes the pager before a batch of records
        'filter' returns a filter for a https:GET
        'endBatch' after a partial poll (recCnt >= self.get_batch_size())
        'complete' after reading the last record in the table
        dict: with each record, so that pager can see each record.
Returns:
    None or dict:
        """
        if isinstance(param, dict):     # called with the current record?
            self.lastId = param[self.idField]  # max(id_field)
            tf = self.timeField
            if tf is not None:          # table has a time field?
                self.maxTime = param[tf]  # last one seen is the maximum value
        elif param == 'filter':         # return a filter for paging hist* table?
            result = {attr_name(self.idField): f"gt({param_str(self.lastId)})"}
            self.filter_talk(f"{self.idField}>{self.lastId}")
            return result
        elif param == 'init':           # initialize?
            self.filterCnt = 0          # print next filtered message
        elif param == 'endBatch':       # Advance nextPoll
            if self.timeField is None:
                self.batch_next_poll(None)
            elif self.timeField_type == 'DateBad':  # Key has Cisco time bug?
                self.batch_next_poll(anyToSecs(date_bad(self.maxTime)))  # *****
            else:  # ***** remove the above after Cisco fixes the time zone bug
                self.batch_next_poll(anyToSecs(self.maxTime))
        elif param == 'complete':       # Schedule nextPoll per table parameters
            self.next_poll_update()
        else:
            logErr(f"{self.tableName} unknown pager function code {param}")
            raise TypeError

    # The poll_pager collects all of the records in a table that represents
    # a collection of pseudo-static entities. I.e. the number and identity
    # of the entities change but slowly. The table is polled periodically to
    # record the changing entity attribute values.
    # If the table has a primary key, the poll_pager returns a filter to GET
    # records after the last read primary key value.
    # If the table does not have a primary key, the poll_pager returns a filter
    # on the ',firstResult' meta-attribute to skip over the count of records
    # read.
    # Assertion with a primary key: record[id_field]<=lastId --> record has been read
    # Assertion w/o a primary key: records 1 through recCnt have been read

    def poll_pager(self, param: object = 'filter') -> dict:
        if isinstance(param, dict):     # called with current record?
            param['polledTime'] = self.polledTime  # stamp record with polling time
            if self.idField is not None:
                self.lastId = param[self.idField]
        elif param == 'filter':         # return a filter for paging a table?
            if self.idField is not None:  # page by primary key if there is one
                result = {attr_name(self.idField): f"gt({param_str(self.lastId)})"}
                self.filter_talk(f"{self.idField}>{self.lastId}")
            elif self.paged:            # No. Does table supports paging?
                result = {'.firstResult': self.recCnt}  # use meta-attribute
                self.filter_talk(f".firstResult>{self.recCnt}")
            else:
                result = dict()         # else no paging parameters may be provided
                self.filter_talk('None')
            return result
        elif param == 'init':           # initialize?
            self.filterCnt = 0          # print next filtered message
            self.zero_id_field()
        elif param == 'endBatch':       # This shouldn't happen for a polled table
            logErr(f"Poll of {self.tableName} stopped at {self.recCnt} records")
            self.next_poll_update()
        elif param == 'complete':       # Schedule nextPoll per table parameters
            self.next_poll_update()
        else:
            logErr(f"{self.tableName} unknown pager function code {param}")
            raise TypeError


class SubTable(Named):
    """Class defines a SubTable, with common attributes inherited by Table."""

    def __init__(self, *fields, keys: list, **kwargs):
        """Create a SubTable

        Parameters:
            keys (list):		[(type:str, field_name:str), ...] of primary keys
            *fields (tuple):	((type:str, field_name:str, include:bool=True), ...)
                    include		True to add to SELECT; None to add ['ignore']=True

        Returns with updated self. attributes:
            .table_name = table_name
            .select = [field_name, ...],
            .key_defs = [(type_string, field_name), ...]
            .fieldTypes = {field_name:{type entry in types}, ...}
            }
        """
        # print(f"SubTable.__init__(fields={fields}, kwargs={kwargs})")
        super().__init__(*fields, **kwargs)
        self.file: Union[_io.TextIOWrapper, None] = None  # output file
        self.file_name: str = ''        # full pathname of output file
        self.select: list = list()      # build SELECT list from an empty list
        self.check_fields: bool = False  # True to check field types
        self.check_enums: bool = False  # True to check enum values
        self.field_counts = defaultdict(lambda: defaultdict(int))  # {field_name:{type(value):count, ...}, ...}
        self.field_values = defaultdict(lambda: defaultdict(int))  # {field_name:{value:count, ...}, ...}
        self.fieldTypes: dict = dict()  # build fieldTypes from an empty dict
        self.key_defs: list = keys
        self.parent: Union[Table, None] = None       # Initially no parent
        self.subTables: dict = dict()   # {pathName:subTable, ...}
        self.writer: Union[csv.DictWriter, None] = None  # (dictWriter): returned from csv.dictWriter

        for afield in keys:             # Add each key ...
            self.field(*afield)         # ... to fieldTypes and SELECT
        for afield in fields:           # Add each field ...
            self.field(*afield)         # ... to fieldTypes [SELECT, iff not 'ignore']
        return

    def close_writer(self, extn: str = 'csv', rename: bool = True):
        """Close the csv.dictWriter' output xxx.tmp file and rename to xxx.csv.

        :param extn:	rename .tmp to .{extn}
        :param rename:	True to close & rename; False to only close
        """
        if self.file is None:  # file wasn't opened
            return
        self.file.close()
        self.file = None
        if rename:
            os.rename(self.file_name + '.tmp', self.file_name + '.' + extn)

    def enum_find(self) -> list:
        """return [(field_name, {value: int, ...}, {int:str, ...}), ...]
        for each field in table which is an enum.
        """
        enums = [(fn, self.fieldTypes[fn]['values']) for fn in self.select
                 if self.fieldTypes[fn]['values'] is not None]
        return [(fn, values, dict([(i, v) for v, i in values.items()]))
                for fn, values in enums]

    def field(self, field_type: str, field_name: str, include: bool = True, first: bool = False):
        """Add a field to fieldTypes [and SELECT].

        Parameters:
            field_type (str):	type of the field
            field_name (str):	name of the field
            include (bool):		True to include in SELECT; None to not check
            first (bool):		insert at beginning of SELECT
        """
        fts = self.fieldTypes
        if include is None:             # ignore checking?
            # add 'check':False to a private shallow copy of the type definition
            fts[field_name] = allTypes[field_type].copy()
            fts[field_name]['check'] = False
        else:                           # use shared type definition dict
            fts[field_name] = allTypes[field_type]
        allTypes[field_type]['UsageCount'] += 1  # increment type's usage count
        if include:                     # ... include the field in the SELECT
            if first:
                self.select.insert(0, field_name)
            else:
                self.select.append(field_name)

    def open_writer(self, file_name: str) -> 'SubTable':
        """Open a csv.dictWriter for the output from this [Sub]Table
        Parameters:
            file_name (str):		pathname (w/o extension) for output file

        """
        if len(self.select) > len(self.key_defs):  # any non-key fields to write?
            self.file_name = file_name
            self.file = open(self.file_name + '.tmp', 'w', newline='')
            self.writer = csv.DictWriter(self.file, fieldnames=self.select, extrasaction='ignore')
            self.writer.writeheader()
        else:                           # no non-key fields to write
            self.file = None  # don't open a file
        return self

    def table_columns(self) -> list:
        """Return column definitions for boto3.client.create_table StorageDescriptor['Columns']."""
        result = []
        for col in self.select:
            typ = self.fieldTypes[col]
            entry = {'Name': col,
                     'Type': typ['hive_type'] if typ['values'] is None else 'VARCHAR'}
            params = getattr(self, 'Parameters', None)
            if params is not None:
                entry['Parameters'] = params
            result.append(entry)
        return result

    def to_hive(self, parent_path: str = None) -> str:
        """Create Hive DDL definition text for a [Sub]Table"""
        if parent_path is None:         # a top-level Table?
            name = f"{self.tableName[0].lower()}{self.tableName[1:]}"
        else:                           # a SubTable
            name = f"{parent_path}_{self.tableName}"
        s = f"CREATE EXTERNAL TABLE IF NOT EXISTS {name} ("
        regex = ''
        first_field = True
        for fieldName in self.select:  # create Hive DDL and regex for the table
            field_type = self.fieldTypes[fieldName]  # the type dict
            if first_field:
                first_field = False
            else:
                s += ',\n'
                regex += ','
            s += f"`{fieldName}` {field_type['hive_type']}"
            regex += field_type['hive_regex']
        if len(self.key_defs) > 0:      # any PRIMARY KEYS?
            s += f'.\nCONSTRAINT {name}_pk PRIMARY KEY ({",".join([k[1] for k in self.key_defs])})'
        s += "') ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe' \n" \
             + "WITH SERDEPROPERTIES ('serialization.format' = '1',\n 'input.regex'='^" + regex + ")\n"
        sub_tables = getattr(self, 'sub_tables', None)
        for table_name in sub_tables:   # add Hive and regex for each sub_table
            st = self.subTables[table_name]
            if len(st.select) > len(st.keys):  # SubTable has data to output?
                s += st.to_hive(name)   # add SubTable's definition to output
        return s

    def to_sql(self, parent_path: str = None) -> str:
        """Create SQL definition text for a [Sub]Table."""
        if parent_path is None:         # a top-level Table?
            name = f"{self.tableName[0].lower()}{self.tableName[1:]}"
        else:  # a SubTable
            name = f"{parent_path}_{self.tableName}"
        s = f"CREATE EXTERNAL TABLE {name}("
        for fieldName in self.select:   # Create SQL DDL for a table
            field_type = self.fieldTypes[fieldName]  # the type dict
            type_name = field_type['sql_type']
            values = field_type['values']
            if isinstance(values, dict) and len(values) > 0:  # an enum?
                s += fieldName + " ENUM ('" + "','".join([str(x) for x in values]) + "'),\n"
            else:
                s += f"{fieldName} {type_name},\n"
        if len(self.key_defs) > 0:      # any PRIMARY KEYS?
            s += f'CONSTRAINT {name}_pk PRIMARY KEY ({",".join([k[1] for k in self.key_defs])}),\n'
        s = s[:-2] + ');\n'
        sub_tables = getattr(self, 'sub_tables', [])
        for table_name in sub_tables:   # add SQL for each subtable
            st = self.subTables[table_name]
            if len(st.select) > len(st.keys):  # SubTable has data to output?
                s += st.to_sql(name)    # add it's definition to output
        return s

    def type_find(self, type_name: str) -> list:
        """return list of all fields in table of type boolean"""
        return [fn for fn in self.select if self.fieldTypes[fn]['name'] == type_name]


class Table(SubTable, Pager):
    def __init__(self, version: str, prefix: str, table_name: str, polled: bool,
                 poll_period: float, recs_per_hour: int, *fields):
        """Create new Table instance.

        Parameters:
            version (str):		API version. e.g. "v1", "v2", "v3", "v4"
            prefix (str):		URL prefix. E.g. "data", "op/devices", ...
        """
        # convert from positional arguments to key-word arguments
        kwargs = {'table_name': table_name, 'polled': polled,
                  'poll_period': poll_period, 'recs_per_hour': recs_per_hour, 'keys': []}
        super().__init__(*fields, **kwargs)  # init
        self.version: str = version     # API version E.g. "v1","v2", ...:
        self.prefix: str = prefix       # URL prefix E.g. "data", "op/devices", ...
        # self.table_name: str = table_name  # table name
        self.generator: callable = defaultGenerator  # generator to iterate records
        # self.select: list				# Fields to select. [field_name, ...]
        # self.fieldTypes: dict	# {field_name:field_type, ...} of each field, field_type in allTypes
        # self.file_name: str = ''		# {epoch_msec}_{table_name}{version}
        self.indexTablePath: Union[str, None] = None  # pathname to index table for main table
        self.checked_time: float = 0.0  # time.time() that enums and fields last checked
        self.prev_polledTime: float = 0.0  # time.time() that previous poll started
        self.queryOptions: dict = dict()  # {attr_name:value, ...] default is: {}

        if self.polled:                 # The table is polled?
            super().field(field_type='float', field_name='polledTime', first=True)
            # keys = [("float", "polledTime")]  # add polling field
            self.pager: Callable = self.poll_pager  # polling pager and helper
        else:                           # No. assume historical pager
            # keys = []					# initially no keys
            self.pager: Callable = self.hist_pager  # historical pager and helper

    # Note: the table definition can override self.pager with .set_pager(...)

    def __str__(self) -> str:           # return a string representation of the table
        s = {'table_name': self.tableName, 'lastId': self.lastId,
             'minSec': strfTime(self.minSec), 'maxTime': strfTime(self.maxTime),
             'nextPoll': strfTime(self.nextPoll), 'recs_per_hour': self.recordsPerHour}
        return str(s)

    def set_id_field(self, id_field: str) -> 'Table':
        """Add a key field, and set value of lastId to min."""
        if self.idField is None:
            self.idField = id_field
        self.lastId = 0 if self.fieldTypes[id_field]['name'] in numericTypes else ''
        self.key_defs.append((self.fieldTypes[id_field]['name'], id_field))  # add id_field to key_defs
        return self

    def set_paged(self, paged: bool = True) -> 'Table':
        """Sets that this table supports CPI paging."""
        self.paged = paged
        return self

    def set_generator(self, generator: object) -> 'Table':
        """Set the generator that reads a batch of records with managed paging."""
        if isinstance(generator, str):  # Name of a built-in generator?
            self.generator = getattr(self, generator)
        else:                           # No -- the actual generator function
            self.generator = generator
        return self

    def set_index_table_path(self, index_table_path: str) -> 'Table':
        self.indexTablePath = index_table_path
        return self

    def set_pager(self, pager: Callable) -> 'Table':
        """Assign the function to supply and manage paging filters for Cpi.Reader.
        pager('init') initializes the pager before a batch of records
        pager('filter') returns a filter for a https:GET
        pager('endBatch') after a partial poll (recCnt >= self.get_batch_size())
        pager('complete') after reading the last record in the table
        pager(dict:) with each record, so that pager can see each record.
        Assumptions:
            CPI returns records by ascending database @id.

        Parameters:
            pager	(str):		name of a pager function in the Table class
                    (function)	a client-supplied pager function
        """
        if isinstance(pager, str):      # Name of a built-in pager?
            self.pager = getattr(self, pager)
        else:                           # No -- the actual generator function
            self.pager = pager
        return self

    def set_query_options(self, opts: dict) -> 'Table':
        """Sets the dictionary of query options text to add to the GET.

        Parameters:
            opts (dict):		{API attribute: value}
        """
        self.queryOptions = opts
        return self

    def set_rollup(self, rollup: float) -> 'Table':
        """Set the data retention seconds after which CPI deletes records"""
        self.rollup = rollup
        return self

    def set_time_field(self, time_field: str) -> 'Table':
        """Set the field_name of a field containing a timestamp for the record."""
        self.timeField = time_field
        if time_field is not None:
            self.timeField_type = self.fieldTypes[time_field]
        return self

    def subTable(self, table_name: str, keys: list, *fields) -> 'Table':
        """Create a child SubTable of this Table

        Parameters:
            table_name (str):	name of SubTable
            keys (list):		[(type:str, field_name:str), ...] of primary keys
            *fields (tuple):	((type:str, field_name:str, include=True), ...)
        Returns:
            self with updated self.subTables[table_name] = SubTable(...)

        """
        self.subTables[table_name] = child = SubTable(table_name=table_name,
                                                      keys=keys, *fields)
        child.parent = self                 # link in SubTable to parent Table
        return self


# 	G E N E R A T O R S

def defaultGenerator(server: Cpi, table: Table, verbose: int = 0):
    """Initialize generator to read a batch of records.

    Parameters:
        server (Cpi.Cpi)	Cisco Prime Infrastructure server instance
        table (Table)		the table to read
        verbose (int)		int verbose diagnostics level or True/False
    """
    table.verbose = verbose_1(verbose)  # table at one level less messages
    table.recCnt = 0

    max_records = table.get_batch_size()  # max number of records to read
    reader = Cpi.Reader(server,
                        '/'.join([table.version, table.prefix, table.tableName]),
                        filters=table.queryOptions, paged=table.paged,
                        verbose=verbose_1(verbose), pager=table.pager)
    table.pager('init')                 # initialize the pager before the reader
    for rec in reader:
        table.recCnt += 1
        table.pager(rec)                # let pager inspect record values
        yield rec
        if reader.recCnt >= max_records:
            break                       # max_records have been read, yet ...
    else:
        table.pager('complete')         # every available record was read
        return
    table.pager('endBatch')             # ... Still more records to read.
    return


# obtain the floor map from v4/maps/{mapId}/image, and
# augment each ServiceDomain floor record with a file_name link to the floor map.
map_path = 'maps'                       # path to the folder of map jpegs


def domainGenerator(server: Cpi, table: Table, verbose: int = 0):
    """GETS the ServiceDomain API and returns records augmented with a mapId (filename) of image.

    Parameters:
        server (Cpi.Cpi)	Cisco Prime Infrastructure server instance
        table (Table)		the table to read
        verbose (int)		int verbose diagnostics level or True/False
    """

    def worker(server: Cpi, id_entry: list, service_rec: dict):
        # Read using cpiapi's default pager, which doesn't know about Table
        # verbose level reduced to prevent thousands of pager messages
        table.pager('init')  # initialize the pager before the reader
        image_response = None
        codes = []
        attr = '@id'
        for attr in ['@id']:        # if recoverable error on first try, try once more
            at_id = service_rec[attr]
            server.rateLimit()          # sleep as necessary to avoid over-running CPI
            try:
                url = server.baseURL + '/'.join([table.version, 'maps', str(at_id), 'image'])
                print(f"url={url}")
                r = requests.get(url,
                                 auth=(server.username, server.password),
                                 verify=False, timeout=server.TIMEOUT)
            except requests.exceptions.ReadTimeout:
                # server.rate_semaphore.get()      # release concurrent count
                server.rate_semaphore.put(None)  # release concurrent count
                logErr(f"{sys.exc_info()[0]} {sys.exc_info()[1]}\n")
                continue
            except requests.exceptions.RequestException:  # e.g. [ConnectionError|TooManyRedirects]
                # server.rate_semaphore.get()      # release concurrent count
                server.rate_semaphore.put(None)  # release concurrent count
                logErr(f"{sys.exc_info()[0]} {sys.exc_info()[1]}\n")
                continue                # Could possibly clear. try again
            # server.rate_semaphore.get()  # release concurrent count
            server.rate_semaphore.put(None)  # release concurrent count
            codes.append(f"{attr}->{r.status_code}")
        # if r.status_code != 200:
        # Doc. states that any error response is coded as requested
        # However, codes 401, 403, and 404 and 403 return html for human
        # print(response)
        # found the record
        # if r.status_code != 200:
        service_rec['file_name'] = f"{codes}"
        return
        # image_response is the image
        for version in id_entry:        # look for an existing file that is equal
            fn = f"{at_id}_{version:4}.png"
            with open(os.path.join(map_path, fn, 'rb')) as png_file:
                png_contents = png_file.read()  # read the entire file
                if pmg_contents == image_response:
                    service_rec['file_name'] = fn
                    return
        # couldn't find equal existing version. Create a new version.
        version = '0001' if len(id_entry) == 00 else int(max(id_entry)) + 1
        fn = f"{at_id}_{version:4}.jpeg"
        with open(os.path.join(map_path, fn), 'wb') as png_file:
            png_file.write(image_response)
        service_rec['file_name'] = fn

    table.verbose = verbose_1(verbose)  # table at one level less level of messages
    table.recCnt = 0
    reader = Cpi.Reader(server, '/'.join([table.version, table.prefix, table.tableName]),
                        filters=table.queryOptions, paged=table.paged,
                        verbose=verbose_1(verbose), pager=table.pager)
    print(f"reader={reader}")
    map_list = os.listdir(map_path)
    print(f"map_list={map_list}")
    maps = {}  # {at_id: [version, ...], ...}
    for fn in map_list:
        m = re.fullmatch(fn, r'([0-9]+)_([0-9]+)\.png')
        if m:                           # correct syntax for map file?
            at_id = m.group(1)
            if at_id in maps:           # already an entry for at_id?
                maps[at_id].append(m.group(2))  # Yes. append to it
            else:                       # No
                maps[at_id] = [m.group(2)]  # create an entry

    domains = []                        # [{ServiceDomain record}, ...]
    print("init")
    table.pager('init')                 # initialize the pager before the reader
    for rec in reader:                  # read the entire table ...
        table.recCnt += 1
        table.pager(rec)                # let pager inspect record values
        domains.append(rec)             # ... into a list
    print(f"len(domains)={len(domains)}")
    for rec in domains:
        if rec['domainType'] not in ('FLOOR_AREA', 'OUTDOOR AREA'):  # domain without image?
            rec['file_name'] = ''       # Yes. Only FLOOR (and OUTDOOR AREA) have images
            continue
        at_id = rec['@id']
        if at_id not in maps:           # Already image file(s) for this at_id?
            maps[at_id] = []            # No. Create an empty list to append to
        worker(server, maps[at_id], rec)  # GET xxx. Find existing equal image file, or create new image file.
        print(f"yield")
        yield rec                       # with augmented file_name field
    table.pager('complete')             # every available record was read
    return


def neighborGenerator(server: Cpi, table: Table, verbose: int = 0,
                      name_regex: str = None, apd_recs: Iterable = None,
                      concurrent: int = None):
    """A generator to read a table by apId=value for each value in ap_ids


    :param server:      CPI server
    :param table:       the Table to read
    :param verbose:     diagnostic messaging level
    :param name_regex:  filter parent table by rec['name']
    :param apd_recs:    Iterable of APD records, or None to get apId from
                        AccessPointDetails
    :param concurrent   Number of concurrent threads
    :return:
    """

    def producer():
        """Queue each AccessPointDetails @id to work_q."""
        nonlocal table, server, work_q
        if apd_recs:
            reader = apd_recs
        else:
            reader = Cpi.Reader(server, tableURL=table.indexTablePath,
                            filters={".full": "true", ".nocount": "true"},
                            paged=True, verbose=verbose_1(verbose))
        for rec in reader:
            if worker_count <= 0:       # All the workers have stopped?
                break                   # Yes, stop producing work
            if name_regex is None or re.match(name_regex, rec['name']):
                work_q.put(rec['@id'])
        for i in range(server.maxConcurrent):  # stop each worker
            work_q.put(None)

    def worker():
        """Get an AP apId from the work_q and pass each record to done_q."""
        nonlocal work_q, done_q, error_ack_q, table, server
        errors = []
        reprocess_item = False
        item = None                     # make IDE checker happy
        while True:
            if not reprocess_item:
                item = work_q.get()     # get an item from the work_q
            reprocess_item = False
            if item is None:            # told to STOP?
                done_q.put(errors)      # tell consumer that I'm done doing work
                break
            # Read using cpiapi's default pager, which doesn't know about Table
            # verbose level reduced to prevent thousands of pager messages
            reader = Cpi.Reader(server,
                                '/'.join([table.version, table.prefix, table.tableName]),
                                filters={'apId': item},
                                verbose=verbose_1(verbose), pager=table.pager)
            table.pager('init')     # initialize pager before iterating the reader
            try:
                for rec in reader:
                    rec['apId'] = item
                    done_q.put(rec)
                if item in errors:      # this success was a retry on the AP?
                    errors.remove(item)  # Yes, remove AP from error list
            except ConnectionAbortedError:  # -> unavailable AP
                if item not in errors:  # first error for this AP?
                    errors.append(item)     # Yes. add to list of error items
                    reprocess_item = True   # and try a second time
            except ConnectionError:
                if reader.result.status_code != 401:  # non-recoverable error
                    # must signal done before [attempt to] put item on work_q
                    done_q.put(None)    # tell consumer that I quit from error
                    done_q.put(errors)  # then tell consumer that I'm done
                    work_q.put(item)    # only then, put item back on work_q
                    break               # exit
                # status_code 401 might just be too much concurrency
                done_q.put(reader.result.status_code)  # give consumer the code
                cmd = error_ack_q.get()  # wait for response
                if cmd:                 # told to reprocess current item?
                    reprocess_item = True
                else:                   # told to quit
                    done_q.put(errors)  # give consumer my errors
                    break               # break out of loop and exit

    table.verbose = verbose_1(verbose)  # reduced message level for table
    name_regex = name_regex             # to filter APs by name
    table.recCnt = 0
    table.pager('init')
    # work_q maxsize must exceed server.maxConcurrent
    maxConcurrent = server.maxConcurrent  # save for restore after
    work_q = Queue(maxsize=max(20, maxConcurrent))  # apId/None producer to workers
    done_q = Queue(maxsize=20)    # dict result/list done workers to consumer
    error_ack_q = Queue(maxsize=10)  # worker waiting for error Ack
    worker_count = server.maxConcurrent

    # start the producer that supplies apId's
    source = threading.Thread(target=producer)
    source.start()
    threads = [source]                  # threads to join when we're done
    # start the workers that lookup rxNeighbor information for an apId
    for i in range(server.maxConcurrent):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    # consume the workers' output and yield records
    table.pager('init')                 # initialize the pager before the reader
    table.errorList = []                # items returning error
    good_cnt = 1                        # empty set is considered OK
    workers_quit = 0                    # number of workers that quit on error
    while worker_count > 0:
        rec = done_q.get()
        if isinstance(rec, dict):       # record, as expected?
            good_cnt += 1               # another good result
            table.recCnt += 1
            table.pager(rec)            # let pager inspect record values
            if good_cnt > 40 and server.maxConcurrent < maxConcurrent:
                server.maxConcurrent += 1  # increase concurrency window
                good_cnt = 10           # need another 40-10=30 for next increase
            yield rec
        elif isinstance(rec, int):      # Possibly recoverable error code?
            if server.maxConcurrent > 2:  # still room to back off?
                server.maxConcurrent += -1  # decrease concurrency
                error_ack_q.put(True)   # release worker to continue
            else:                       # too many failures
                error_ack_q.put(False)  # tell worker to quit
        elif rec is None:               # A worker quit on error?
            good_cnt = 0                # most recent .get is an error
            workers_quit += 1           # one more worker quit on error
        elif isinstance(rec, list):     # Worker is done?
            table.errorList += rec      # include worker's errors in errorList
            worker_count -= 1           # one less worker is running
        else:                           # Internal error
            logErr(f"Internal error in neighborGenerator")
            sys.exit(1)
    if workers_quit > 0:
        logErr(f"{workers_quit} of {server.maxConcurrent} workers received error response and quit")
    if good_cnt == 0:  # last result was an error --> didn't finish
        # Producer might yet queue 1 work + maxConcurrent stop commands
        # Safe only because no other thread is doing work_q.get()
        # Unblock producer by removing remaining items from the work_q
        while work_q.qsize() > 0:
            work_q.get()
    # all workers have exited, work has been consumed, and producer unblocked
    server.maxConcurrent = maxConcurrent  # restore window size
    for t in threads:                   # join all of the threads together
        t.join()
    if good_cnt == 0:                   # error(s) not recovered?
        raise ConnectionError           # tell the caller
    table.pager('complete')             # every available record was read


TAU = 1000                  # factor for exponential integration
jitter_secs = 15.0  # seconds to delay from predicted updateTime to start of next poll
slew_seconds = 10.0         # Maximum increment to increase the period


def real_timeCS(server: Cpi, table: Table, verbose: int = 0):
    """Initialize generator to read a batch of records.

    Parameters:
        server (Cpi.Cpi)	Cisco Prime Infrastructure server instance
        table (Table)		the table to read
        verbose (bool)		int verbose diagnostics level or True/False
    Algorithm
    The traffic data in ClientSessions is clearly polled on a period that is
    generally about 5 minutes, although occasionally a poll is skipped or delayed.
    Interference effects between similar periods for CPI's sampling and our blind
    sampling would cause odd data. E.g. some missed samples or data samples that
    alternate between no data and catch-up data.

    The ClientSessions API needs an updateTime in order to be generally useful. Not
    only would an updateTime clarify the data, it would also allow our polling to
    avoid the load of over-sampling and minimize information delay by phase-locking
    our polling to CPI's updateTimes.

    The ClientSessions and ClientDetails views contain largely overlapping data, with
    one huge difference -- ClientDetails correctly includes the updateTime. The
    approach is to poll ClientDetails to phase-lock our polling to the updateTimes,
    then join from ClientDetails (CD) to ClientSessions (CS) on
    CS.macAddress_octets=CD.macAddress_octets and CS.sessionStartTime=CD.associationTime
    to add the updateTime and other fields to the combined view.

    This view's poll-period should initially be about 3/4 the expected data
    collection period, so that it does not miss records while learning the period.
    If the actual collection period is less than expected,
    quickly notice and reduce the polling period.
    If the actual collection period is significantly longer than expected,
    avoid reacting to temporary sampling
    skips/delays by conservatively increasing the polling period by no more
    than 'slew_rate' seconds.

    At the start of each poll, the generator has the previously polled CS and CD
    records in dictionaries with most or all of the CS records augmented with
    CD.updateTime and any additional CD data. The previous CS records have already
    been accounted for in the output. The generator contemporaneously reads a new
    poll of CS records and CD records into their respective dictionaries,
    matches each CD record to a CS record, and augments the new CS record.

    The generator builds a dict of votes for predicting the next updateTime.
    For each new CD record, it finds the corresponding previous CD record. If found,
    and not an duplicate record, it votes a predicted next updateTime
    new.updateTime + (new.updateTime - old.updateTime) into the histogram.

    For each new CS (generally augmented) and old record for a primary key:
    - if a new record was not matched with CD, thus does not have an updateTime:
        - if new.sessionStartTime is more recent than the previous polledTime
            - use new.sessionStartTime as new.updateTime
        - elif new.sessionEndTime < new.PolledTime + delta
            - use new.sessionEndTime as new.updateTime
        - else log an unexpected condition, use PolledTime as updateTime
    - elif both records have updateTimes
        - if updateTimes are equal, log any inequalities, mark to not output
        - else: pass
    - elif the new, but not old, record has an updateTime
    - output each record, unless marked not to.
    replace CS.old with CS.new and CD.old with CD.new

    The predicted updateTime is the median vote of the individual predictions.
    Adjust the polling phase (i.e. delay until next poll) to occur jitter seconds
    after the predicted updateTime, and adds the predicted period into the
    expected period integrator.
    It schedules the next poll for N seconds after a time:
    - if predicted is < the phase-lock window: then the predicted updateTime
    - otherwise, the middle of the (updated) phase-lock window with width 2*N.
    """
    global old_cd, old_cs, new_cd, new_cs

    def compare_rec(old_rec: dict, new_rec: dict) -> str:
        diffs = []
        for attr in old_rec:
            old = old_rec.get(attr, None)
            new = new_rec.get(attr, None)
            if old != new:
                diffs.append(f"{attr} {old}->{new}")
        return ', '.join(diffs)

    def not_matched(cd_rec: dict):
        """log that this CD record did not match a CS record"""
        nonlocal counts
        counts['CD did not match any CS'] += 1  # increment count
        if verbose < 2:                 # skip the details?
            return
        print(cd_rec['macAddress']['octets'], 'no CD to CS match: assoc, update',
              strfTime(cd_rec['associationTime']), strfTime(cd_rec['updateTime']),
              cd_rec['status'])

    def cs_cd_diffs(cs_rec: dict, cd_rec: dict) -> str:
        """Compare cs and cd fields in common. Return differences text or None if equivalent."""
        nonlocal common_fields
        if common_fields is None:       # calculate the set of fields in common?
            common_fields = set([k for k in cs_rec]) & set([k for k in cd_rec])
            common_fields -= {'@displayName', '@id', 'ipAddress', 'polledTime', 'userName'}
        diffs = []
        for k in common_fields:
            try:                        # to recover if record format has changed
                if cs_rec[k] != cd_rec[k]:  # difference n fields?
                    diffs.append(f"{k}: {cs_rec[k]}!={cd_rec[k]}")
            except KeyError:            # a field is missing
                logErr(f"field {k} missing at {strfTime(cd_rec['updateTime'])}")
                common_fields = set([k for k in cs_rec]) & set([k for k in cd_rec])
                common_fields -= {'@displayName', '@id', 'ipAddress', 'polledTime', 'userName'}
            except ValueError:          # a field had different types
                logErr(f"{k} {cs_rec[k]}?={cd_rec[k]} at {cd_rec['updateTime']}")
        return None if len(diffs) == 0 else ', '.join([s for s in diffs])

    if table.prev_polledTime < time.time() - 3*table.pollPeriod:
        table.prev_polledTime = time.time() - 3*table.pollPeriod  # reasonable startup
    table.verbose = verbose_1(verbose)  # table at one level less messages
    table.recCnt = 0                    # initialize 0 records read
    table.pager('init')
    filters: dict = table.queryOptions
    # Select only the sessions that are active since jitter before the last poll
    # Jitter offset may repeat some records, but avoids missing some
    filters['sessionEndTime'] = f"gt({int(1000*(table.prev_polledTime - jitter_secs))})"
    reader = Cpi.Reader(server,
                        '/'.join([table.version, table.prefix, 'ClientSessions']),
                        filters=filters, paged=True,
                        verbose=verbose_1(verbose), pager=table.pager)
    table.pager('init')                 # initialize the pager before the reader
    for rec in reader:
        table.pager(rec)                # let pager inspect record values
        # don't bother updating table.minSec or using idField
        mac = rec['macAddress']['octets']
        if mac in new_cs:               # already a new record with this mac?
            new_cs[mac].append(rec)     # yes. insert another
        else:
            new_cs[mac] = [rec]

    from .cpitables import archive      # in lower scope to avoid cyclic import
    # Poll the ClientDetails table into new_cd, join to CS
    vote_poll = defaultdict(int)  # Dict(1, 0)              # {next updateTime: count, ...}
    vote_period = defaultdict(int)  # Dict(1, 0)            # {period_secs, count, ...}
    vote_update = defaultdict(int)  # Dict(1, 0)
    counts = defaultdict(int)  # Dict(1, 0)                 # message counters
    common_fields = None
    cd_table = find_table('ClientDetails', [archive])  # copy of this table to avoid concurrent use
    filters = cd_table.queryOptions.copy()
    filters['updateTime'] = f"gt({int(1000*(table.prev_polledTime - jitter_secs))})"  # exclude older data
    filters['associationTime'] = f"gt({0})"  # exclude updates to devices never associated
    api = '/'.join([cd_table.version, cd_table.prefix, cd_table.tableName])
    cd_reader = Cpi.Reader(server, api, filters=filters,
                           paged=True,
                           verbose=verbose_1(verbose), pager=cd_table.pager)
    cd_table.pager('init')              # initialize the pager before the reader
    new_cd = {}
    rec_cnt = 0                         # number of CD records
    for cd_rec in cd_reader:
        cd_table.pager(cd_rec)          # let the pager have a look
        mac = cd_rec['macAddress']['octets']  # client mac address
        associationTime = cd_rec['associationTime']
        vote_update[int(cd_rec['updateTime']/1000)] += 1
        matched = False                 # matched the record to a cs record?
        drop = False                    # drop this record?
        cs_lst = new_cs.get(mac, None)  # [rec, ...]
        if cs_lst is not None:          # Found this macAddress?
            for cs_rec in cs_lst:       # Yes. Attempt to join to a cs record
                if associationTime != cs_rec['sessionStartTime']:  # wrong session?
                    continue            # Yes
                if 'updateTime' in cs_rec:  # Already matched?
                    continue            # Yes. try the next
                matched = True          # match with this one
                s = cs_cd_diffs(cs_rec, cd_rec)
                if verbose > 1 and s is not None:  # differences to report
                    print(f"{strfTime(cd_rec['updateTime'])} cs!=cd {s}")
                for attr in ('apSlotId', 'updateTime'):  # copy some fields from cd to cs
                    cs_rec[attr] = cd_rec[attr]
                if cd_rec['updateTime'] == cs_rec['sessionEndTime']:
                    counts['updateTime==sessionEndTime'] += 1
                    drop = True         # might not be a regular poll
        if not matched:
            not_matched(cd_rec)
        # do not include matches of sessionStart and sessionEnd
        if drop:
            continue
        rec_cnt += 1
        if cd_rec['associationTime'] == cd_rec['updateTime']:  # start of a session?
            counts['updateTime==associationTime'] += 1  # Yes
            continue                    # Not needed to stamp ClientSessions
        if mac in new_cd:               # already a record for the mac?
            counts['multi-records per MAC'] += 1
        new_cd[mac] = cd_rec            # only keep the latest record

    # Vote for the updateTime sampling period and new updateTime
    # Transfer new_cd records to old_cd
    for mac, new_rec in new_cd.items():
        old_rec = old_cd.get(mac, None)
        old_cd[mac] = new_rec           # copy to old_cd
        if old_rec is None:             # a previous record with same mac?
            continue                    # No. Can't use to predict next updateTime
        old_msec = old_rec['updateTime']  # Yes
        new_msec = new_rec['updateTime']
        if old_msec != new_msec:        # and updateTimes are different?
            vote_poll[int((new_msec + (new_msec - old_msec))/1000)] += 1
            vote_period[int((new_msec - old_msec)/1000)] += 1
    new_cd = {}                         # done with new CD records
    vote_poll = [(k, cnt) for k, cnt in vote_poll.items()]
    vote_period = [(k, cnt) for k, cnt in vote_period.items()]
    vote_poll.sort()                    # votes sorted by updateTime
    vote_period.sort()                  # votes sorted by updateTime
    vote_update = [(k, cnt) for k, cnt in vote_update.items()]
    vote_update.sort()                  # votes sorted by updateTime

    counts['votes'] = sum([v for k, v in vote_period])
    # yield each new record, with refinements, if not a duplicate
    for mac, cs_lst in new_cs.items():
        for cs_rec in cs_lst:
            key = mac + str(cs_rec['sessionStartTime'])
            csd_rec = cs_rec.copy()     # make a copy to yield to the client
            del cs_rec['polledTime']    # get out of the way for equality tests
            if 'updateTime' not in cs_rec:  # not matched with CD?
                if cs_rec['sessionStartTime'] > table.prev_polledTime:  # new session?
                    # Yes. Makes sense that CD could have missed it.
                    updateTime = cs_rec['sessionStartTime']  # better time-stamp
                else:  # No known reason why. Guess secs->msec avg for updateTime
                    logErr(f"CD poll missed CS {key} at {table.polledTime}")
                    updateTime = int((table.polledTime + table.prev_polledTime)*500)
                csd_rec['updateTime'] = cs_rec['updateTime'] = updateTime
            elif key in old_cs:         # cs_rec was matched. Have old record for this key?
                old_rec = old_cs[key]   # Yes
                if old_rec.get('updateTime', None) == cs_rec['updateTime']:
                    if old_rec == cs_rec:  # same updateTime and == contents?
                        csd_rec['dupl'] = True  # Yes, a duplicate not to be output
                # else:				    # same updateTimes, but different contents
                # This happens occasionally apparently 2nd record is the end of a session
                # 	if not (old_rec['sessionEndTime'] == 4102444800000
                # 			and cs_rec['sessionEndTime'] != 4102444800000):  # session ended?
                # 		logErr(f"CSD session close at AP={cs_rec['apMacAddress']['octets']}"
                # 			+ compare_rec(old_rec, cs_rec))  # Yes. log
                else:                   # new cs_rec has updateTime, but old does not
                    pass                # assume it's a new record
            else:                       # cs_rec has updateTime & no old record
                pass                    # just output
            if 'dupl' in csd_rec:       # duplicate?
                continue                # Yes, do not yield
            for attr in ('apSlotId', 'updateTime'):
                if attr not in csd_rec:  # if attribute was not joined
                    csd_rec[attr] = 0   # add a zero value for consistency
            table.recCnt += 1
            yield csd_rec
        old_cs[key] = cs_rec  # last record always defined. if list is there, it's not empty
    new_cs = {}                         # done with new_cs

    # remove records from old_cs and old_cd that are older than 4 periods
    retention_secs = table.polledTime - 4*table.pollPeriod
    keys = [k for k, v in old_cs.items() if v['updateTime']/1000 < retention_secs]
    for k in keys:
        counts['cs purged'] += 1
        del old_cs[k]
    keys = [k for k, v in old_cd.items() if v['updateTime']/1000 < retention_secs]
    for k in keys:
        counts['cd purged'] += 1
        del old_cd[k]

    lst = [(k, v) for k, v in counts.items()]
    lst.sort()
    print(f"{rec_cnt} total new CD", '. '.join([f"({v}):{k}" for k, v in lst]))

    # Complete. Don't call table.pager('complete'), because it updates the nextPoll, ...
    table.prev_polledTime = table.polledTime  # save this polled seconds as previous
    min_update = vote_update[0][0]
    printIf(verbose, 'update ' + ', '.join([f"{int(d - min_update)}:{cnt}" for d, cnt in vote_update]))
    if len(vote_period) > 0:            # any data to learn from?
        # Yes. find minimum updateTime and median voted period
        min_update_sec = vote_poll[0][0]  # minimum next updateTime
        num_votes = sum([cnt for k, cnt in vote_period])
        middle = num_votes/2
        median_period_sec = 0           # keep the code analyser happy
        for (k, cnt) in vote_period:
            middle -= cnt
            if middle <= 0:
                median_period_sec = k
                break
        printIf(verbose, f"{num_votes} votes median_period_sec={median_period_sec}")
        printIf(verbose, 'period ' + ', '.join([f"{d}:{cnt}" for d, cnt in vote_period]))
        printIf(verbose, 'next ' + ', '.join([f"{int(d - table.polledTime)}:{cnt}" for d, cnt in vote_poll]))
        new_period = table.pollPeriod*pow(((TAU - 1) + median_period_sec/table.pollPeriod)/TAU, num_votes)
        printIf(verbose, f"period {table.pollPeriod} --> {new_period}")
        table.nextPoll = table.polledTime + 298  # just poll every 5 minutes
        if new_period > table.pollPeriod + slew_seconds:
            new_period = table.pollPeriod + slew_seconds  # limit rate of increase
        table.pollPeriod = new_period
    else:                               # No data. Use the period - jitter
        table.nextPoll = table.polledTime + table.pollPeriod - jitter_secs
    return


def real_timeGen(server: Cpi, table: Table, verbose: int = 0):
    """Initialize generator to read a batch of records.

    Parameters:
        server (Cpi.Cpi)	Cisco Prime Infrastructure server instance
        table (Table)		the table to read
        verbose (bool)		int verbose diagnostics level or True/False
    Algorithm
    ***** convert period-learning log to that used by real_time_cs *****
    The table's poll-period should be set to 3/4 the expected data collection
    period. If the actual collection period is less than expected, this generator
    will notice immediately and reduce the polling period to 3/4 the observed
    collection period. If the actual collection period is longer than expected, this
    generator will increase the polling period by no more than 'slew_rate' seconds.
    On each poll, the generator initializes a collection period histogram and
    reads the raw records into a dictionary.
    For each received record, it examines the dictionary of the previous poll.
    If the record is a duplicate, it is ignored.
    If it is a newer version of a previously seen record, the generator yields
    the record, increments the collection period histogram, and replaces
    the record in the previous dictionary with the new record.
    At completion, but before returning, it:
    - calculates the observed collection period(s) and updates the poll period
    - removes each record that is over 5 periods old from the previous dictionary
    """

    table.verbose = verbose_1(verbose)  # table at one level less messages
    table.recCnt = 0
    table.pager('init')
    id_field = table.idField            # primary key
    time_field = table.timeField        # must be epoch msec
    filters: dict = table.queryOptions
    # add timeField > minSec - 1 minute to the filters
    # Time offset may repeat some of the previous update, but avoid missing some updates
    filters[attr_name(table.timeField)] = f"gt({param_str(max(0, table.minSec - 60*1000))})"
    reader = Cpi.Reader(server, '/'.join([table.version, table.prefix, table.tableName]),
                        filters=filters, verbose=verbose_1(verbose), pager=table.pager)
    table.pager('init')                 # initialize the pager before the reader
    votes = defaultdict(int)  # Dict(1, 0)                  # {delta: count, ...}
    period = table.pollPeriod
    for rec in reader:
        table.pager(rec)                # let pager inspect record values
        pri_id = rec[id_field]
        msec = rec[time_field]          # record update time in msec
        table.minSec = max(table.minSec, msec)  # maximum timeField value
        prev_msec = table.prev_poll.get(pri_id, None)
        if prev_msec is None:           # seen this id recently?
            table.prev_poll[pri_id] = msec  # No. Enter into prev_poll
            table.recCnt += 1
            yield rec                   # and output this new record
            continue
        elif prev_msec == msec:         # Yes. Same collection_time?
            continue                    # Yes, ignore duplicated record
        # No, this is a new collection time for pri_id
        delta = (msec - prev_msec)/1000.0  # convert msec --> seconds
        votes[int(delta)] += 1
        period = ((TAU - 1)*period + delta)/TAU
        table.prev_poll[pri_id] = msec
        table.recCnt += 1
        yield rec
    table.pager('complete')             # every available record was read

    table.pollPeriod = int(period)      # convert back to integer poll period
    print(', '.join([f"{d}:{cnt}" for d, cnt in votes.items()]))
    return


def param_str(val) -> str:
    """Format val as URL parameter. E.g. string to 'value' and non-string to str(value)."""
    if isinstance(val, str):            # string value?
        return "'" + val + "'"          # enclose in single quotes
    elif isinstance(val, bool):         # boolean value?
        if val:
            return "true"               # CPI likes lowercase true/false
        return "false"
    else:
        return str(val)


def attr_name(s: str) -> str:
    """Removes initial '@' from s, if present.  To map CPI's @name-->name"""
    return s[1:] if s[0] == '@' else s


def date_bad(val: str) -> str:
    """Correct  Cisco's incorrect zone handling, with a timezone offset"""
    # The +HHMM offset marks values as having been corrected
    if val[-1] != 'Z':
        return val
    if val < '2019-11-03T10:00:00.000Z':  # summer 2019
        return val[:-1] + '+0400'
    elif val < '2020-03-08T11:00:00.000Z':  # winter 2019-2020
        return val[:-1] + '+0500'
    elif val < '2020-11-01T10:00:00.000Z':  # summer 2020
        return val[:-1] + '+0400'
    else:  # Hopefully, Cisco fixes applied before summer 2021 *****
        return val[:-1] + '+0500'


def find_table(table_name: str, dicts: list, version: int = None, best_version=False) -> Table:
    """
    Parameters:
        table_name (str)	name of the table or subtable
        dicts (list)		list of dictionaries to search in
        version (int)		version number. Default (None) find maximum version
        best_version (bool) find table with minimum table.version>=version
    Returns:
        SubTable
    """
    table_name, s, sub_name = table_name.partition('_')
    result = None                       # table hasn't yet been found
    result_version = 999 if best_version else -1  # best version found so far
    for d in dicts:                     # search in each dictionary
        tbls = d.get(table_name, None)
        if tbls is None:                # table defined in this dictionary?
            continue                    # No, keep looking
        for t in tbls:                  # t in [table, ...]
            tbl = t
            if len(sub_name) > 0:       # table_name included subtable?
                tbl = t.subTables.get(sub_name, None)
                matched = tbl is not None
            else:
                matched = True
            if matched:                 # found an exact match on name path?
                ver = int(t.version[1:])
                if version is None:     # looking for maximum version?
                    if ver > result_version:  # Yes. This table is better?
                        result_version = ver  # Yes, remember version
                        result = tbl    # and table
                elif version == ver and result is None:  # first exact version
                    return tbl
                elif best_version:
                    if version <= ver < result_version:  # better version?
                        result_version = ver  # yes
                        result = tbl    # this tbl is a better match
                else:                   # no match
                    pass
    return result


def to_enum(types: dict) -> str:
    """Return ENUM DDL for every ENUM in types"""
    s = ''
    for type_name in types:
        values = types[type_name]['values']
        if isinstance(values, dict):
            s += f"CREATE TYPE {type_name} AS ENUM ('" + "','".join([str(x) for x in values]) + "');\n"
    return s


def report_type_uses(limit: int = 0):
    """Reports each type definition that defines less than 'limit' fields"""
    for typeName, typeVal in allTypes.items():
        if limit == 0 or typeVal['UsageCount'] < limit:
            print(f"{typeName} used {typeVal['UsageCount']} times")
