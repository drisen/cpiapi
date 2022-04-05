#! /usr/bin/python3
# cpiTables.py is Copyright 2019 by Dennis Risen, Case Western Reserve University
#
"""
Contains the archive, production, real-time, and test catalogs of the
relational table definition for each CPI API version's actual response
(generally different from Cisco documentation) that was used by some version of
production performance metrics collection.
"""

from .cpitable import Table, report_type_uses
from .cpitable import neighborGenerator, real_timeCS


def add_table(tables: dict, table: Table):
    """Add a Table to the dictionary

    Parameters:
        tables (dict):	the dictionary to add to
        table (Table)	the Table to add
    """
    if table.tableName in tables:
        tables[table.tableName].append(table)
    else:
        tables[table.tableName] = [table]


# quantities to estimate record volume
MINUTE = 60.0           # seconds in a minute
HOUR = 60*MINUTE        # seconds in an hour
DAY = 24*HOUR           # seconds in a day

NUMAP = 4900            # number of APs
NUMBLD = 145            # number of buildings
NUMCTL = 16             # number of controllers
NUMDOM = 4              # number of domains
NUMDEV = 32             # number of devices
NUMFLOOR = 4            # avg number of floors/building
NUMSSID = 8             # avg number of SSID with data
NUMVIRT = 3             # number of virtual domains
# number of records/hour in the composite Historical* tables
NUMHIST = ((NUMAP + 1)*(NUMSSID + 1 + 2) + 2*NUMDEV*(NUMSSID + 1 + 1) + 2*NUMDEV
           + (NUMBLD*NUMFLOOR)*(NUMSSID + 1) + (NUMSSID + 1 + 2)*NUMDOM + NUMVIRT*(7*NUMDOM)
           )
SAMPERHR = 60/5         # samples/hour in HistoricalClient[Counts|Traffics]

archive = dict()        # dict of archived table definitions
production = dict()     # dict of production tables to collect
real_time = dict()      # dict of production tables to collect real-time
test = dict()           # dict of table definitions for unit testing
all_table_dicts = [production, real_time, archive, test]  # all known tables

# Poll daily shortly after midnight
# Each poll takes less than 3 minutes. Most are just a few seconds.
offset = 5*60.0         # first daily poll starts at 0+5=5 minutes after midnight
'''
WCSDBA 	ACCESSPOINTS
select ap.wirelessaccesspoint_id as id, ap.macAddress as macAddress, ap.lradName as name,
    replace(ap.ipAddress_address,' ','') as ipAddress, ap.ipAddress_address as originalIpAddress,
    ap.ipAddress_addressType as ipAddressT, nr.authentityid as authentityId, nr.authentityclass as authentityClass,
    ap.apLocation as maplocation, ap.softwareVersion as softwareVersion, ap.model as model,
    ap.serialNumber as serialNumber, coalesce(ap.dot11aClientCount, 0) as clientCount_5GHz,
    coalesce(ap.dot11bClientCount, 0) as clientCount_2_4GHz,
    coalesce(ap.dot11aClientCount, 0) + coalesce(ap.dot11bClientCount, 0) as clientCount,
    ap.apType_value as apType_value, ap.ethernetMac as ethernetMac, ap.adminStatus as adminStatus,
    case when mei.managementaddress is not null then ap.apUpTime else null end as upTime,
    ap.status as status, nr.classname as type,
    case when nr.classname='UnifiedAp' then nr.bootVersion else null end as nfdApInf_bootVersion,
    case when nr.classname='UnifiedAp' then nr.iosVersion else null end as nfdApInf_iosVersion,
    case when nr.classname='UnifiedAp' then nr.apcerttype else null end as nfdApInf_apCertType,
    case when nr.classname='UnifiedAp' then nr.linkLatencyEnable else null end as NFDAPINF_LNKLTNCYENBLD,
    case when nr.classname='UnifiedAp' then nr.preStandardState else null end as NFDAPINF_PRSTNDRDSTT,
    case when nr.classname='UnifiedAp' then nr.apStaticEnable else null end as NFDAPINF_PSTTCENBLD,
    case when nr.classname='UnifiedAp' then nr. monitorOnlyMode else null end as nfdApInf_apMode,
    wlc.name as NFDAPINF_CNTRLLRNM,
    case when nr.classname='UnifiedAp' then ipdns.managedaddress else null end as NFDAPINF_LLRIPADDRSS4,
    case when nr.classname='UnifiedAp' then nr.primaryMwar else null end as nfdApInf_primaryMwar,
    case when nr.classname='UnifiedAp' then nr.secondaryMwar else null end as nfdApInf_secondaryMwar,
    case when nr.classname='UnifiedAp' then nr.tertiaryMwar else null end as nfdApInf_tertiaryMwar,
    case when nr.classname='UnifiedAp' then nr.selectedCountryCode else null end as NFDAPINF_CONTRYCODE,
    case when nr.classname='UnifiedAp' and mei.managementaddress is not null 
        then nr.lwappUpTime else null end as nfdApInf_capwapUpTime,
    case when nr.classname='UnifiedAp' then nr.lwappJoinTakenTime else null end as NFDAPINF_CPWPJNTKNTM,
    case when nr.classname='UnifiedAp' then nr.apWipsEnable else null end as nfdApInf_wIPSEnabled,
    case when nr.classname='UnifiedAp' then nr.switchPort else null end as nfdApInf_portNumber,
    case when nr.classname='UnifiedAp' then nr.statsCollectionInterval else null end as NFDAPINF_STTSTCSTMR,
    case when nr.classname='UnifiedAp' then nr.poeStatus else null end as nfdApInf_poeStatus,
    case when nr.classname='UnifiedAp' then (case when (nr.poeStatus between 1 and 7)
        then nr.poeStatus else 5 end) else null end as nfdApInf_poeStatusEnum,
    case when nr.classname='UnifiedAp' then nr.rogueDetectionEnabled else null end as NFDAPINF_RGDTCTNENBLD,
    case when nr.classname='UnifiedAp' then nr.apEncryptionEnable else null end as nfdApInf_NCRYPTNENBLD,
    case when nr.classname='UnifiedAp' then nr.apTelnetStatus else null end as nfdApInf_telnetEnabled,
    case when nr.classname='UnifiedAp' then nr.apSSHStatus else null end as nfdApInf_sshEnabled,
    case when nr.classname='UnifiedAp' then nr.hreapofficeextendapenable else null end as NFDAPINF_FLXCNNCTMD,
    case when nr.classname='UnifiedAp' then nr.powerinjectorselection else null end as NFDAPINF_PWRINJCTRSTT,
    case when nr.classname='UnifiedAp' then nr.groupvlanname else null end as nfdApInf_grpVlnName,
    case when nr.classname='UnifiedAp' and wlc.isEwlc = 1 then nr.siteTagName else null end as nfdApInf_siteTagName,
    case when nr.classname='UnifiedAp' and wlc.isEwlc = 1 then nr.rfTagName else null end as nfdApInf_rfTagName,
    case when nr.classname='UnifiedAp' and wlc.isEwlc = 1 then nr.policyTagName else null end as nfdApInf_policyTagName,
    case when nr.classname='UnifiedAp' and wlc.isEwlc = 1 then case when nr.tagSource between 1 and 6
        then nr.tagSource else 5 end else null end as nfdApInf_tagSource,
    case when nr.classname='AutonomousAp' then nr.reachable else null end as autonomousAP_reachable,
    case when nr.classname='AutonomousAp' then nr.wgbStatus else null end as autonomousAP_wgbStatus,
    case when nr.classname='AutonomousAp' then mne.sysObjectId else null end as autonomousAP_sysObjectId,
    case when nr.classname='AutonomousAp' then mne.sysLocation else null end as autonomousAP_sysLocation,
    case when nr.classname='AutonomousAp' then controllerNr.description else null end as autonomousAP_description,
    case when nr.classname='AutonomousAp' then mne.sysContact else null end as autonomousAP_sysContact,
    nr.lradmneid as ap_mne, sd.id as serviceDomainId, sd.heirarchyname as location_hierarchy,
    case when ap.xcoordinate >= 0 and ap.ycoordinate >= 0 then ap.xcoordinate else null end as xcoordinate,
    case when ap.xcoordinate >= 0 and ap.ycoordinate >= 0 then ap.ycoordinate else null end as ycoordinate,
    case when ap.xcoordinate >= 0 and ap.ycoordinate >= 0 then ap.zcoordinate else null end as zcoordinate,
    case when nr.classname='UnifiedAp' then fcapnv.reapApVlanEnable else null end as nfdApInf_vlanEnable,
    case when nr.classname='UnifiedAp' and fcapnv.reapApVlanEnable = 1 then fcapnv.reapApNativeVlanId
        else null end as nfdApInf_nativeVlanId,
    case when nr.classname='UnifiedAp' then fcg.reapGroupName else null end as nfdApInf_flexConnectGroupName,
    case when nr.classname = 'UnifiedAp' AND ap.adminstatus = 1 AND nr.associatedswitchid IS NOT NULL THEN 1
        when nr.classname = 'UnifiedAp' AND ap.adminstatus = 1 AND nr.associatedswitchid IS NULL THEN 2
        when nr.classname = 'AutonomousAp' AND ap.adminstatus IN (1, 2) then ap.adminstatus
        else 0 end as reachabilityStatus, lmd.meshRole as lradMeshNode_meshRole,
    ap.maintenanceMode as maintenanceMode,
    case when nr.classname = 'UnifiedAp' and nr.apLastDissociatedTimeStamp > 0
        then NUMTODSINTERVAL (nr.apLastDissociatedTimeStamp / 1000 , 'SECOND')
            + to_timestamp_tz('1970-01-01 UTC', 'YYYY-MM-DD TZR') at local
        else null end as apLastDissociatedTimeStamp,
    case when nr.classname = 'UnifiedAp' and nr.apLastAssociatedTimeStamp > 0
        then NUMTODSINTERVAL (nr.apLastAssociatedTimeStamp / 1000 , 'SECOND')
            + to_timestamp_tz('1970-01-01 UTC', 'YYYY-MM-DD TZR') at local
        else null end as apLastAssociatedTimeStamp
from WirelessAccessPoint ap left outer join NetworkResource nr on ap.wirelessAccessPoint_id=nr.id
    left outer join NetworkElement mne on mne.networkelement_id = ap.rawmanagingmne_id
    left outer join WlanControllerWithType wlc on wlc.mneid=mne.networkelement_id
    left outer join NetworkResource controllerNr on ap.rawmanagingmne_id=controllerNr.id
    left outer join ManagedElementInterface mei on mei.id = controllerNr.managedelementinterface_id
    left outer join IpAddressToDnsMapping ipdns on ipdns.mapping_id = mei.id
    left outer join BaseServiceDomain sd on sd.id = ap.rawservicedomain_id
    left outer join HReapApNativeVlan fcapnv on ap.wirelessAccessPoint_id = fcapnv.parentid
    left outer join (
        select alfc.sysMacAddress as macAddress, agfc.parentid as controllerId, agfc.reapGroupName as reapGroupName
        from ApListHreap alfc left outer join APGroupsHreap agfc on alfc.parentid = agfc.id)
            fcg on ap.ethernetMac = fcg.macAddress and fcg.controllerId = wlc.id
    left outer join LradMeshNode lmd on ap.wirelessAccessPoint_id=lmd.parentId
    select ap.wirelessaccesspoint_id as id, ap.macAddress as macAddress, ap.lradName as name,
    replace(ap.ipAddress_address,' ','') as ipAddress, ap.ipAddress_address as originalIpAddress,
    ap.ipAddress_addressType as ipAddressT, nr.authentityid as authentityId, nr.authentityclass as authentityClass,
    ap.apLocation as maplocation, ap.softwareVersion as softwareVersion, ap.model as model,
    ap.serialNumber as serialNumber, coalesce(ap.dot11aClientCount, 0) as clientCount_5GHz,
    coalesce(ap.dot11bClientCount, 0) as clientCount_2_4GHz,
    coalesce(ap.dot11aClientCount, 0) + coalesce(ap.dot11bClientCount, 0) as clientCount,
    ap.apType_value as apType_value, ap.ethernetMac as ethernetMac, ap.adminStatus as adminStatus,
    case when mei.managementaddress is not null then ap.apUpTime else null end as upTime, ap.status as status,
    nr.classname as type, case when nr.classname='UnifiedAp' then nr.bootVersion else null end as nfdApInf_bootVersion,
    case when nr.classname='UnifiedAp' then nr.iosVersion else null end as nfdApInf_iosVersion,
    case when nr.classname='UnifiedAp' then nr.apcerttype else null end as nfdApInf_apCertType,
    case when nr.classname='UnifiedAp' then nr.linkLatencyEnable else null end as NFDAPINF_LNKLTNCYENBLD,
    case when nr.classname='UnifiedAp' then nr.preStandardState else null end as NFDAPINF_PRSTNDRDSTT,
    case when nr.classname='UnifiedAp' then nr.apStaticEnable else null end as NFDAPINF_PSTTCENBLD,
    case when nr.classname='UnifiedAp' then nr. monitorOnlyMode else null end
        as nfdApInf_apMode, wlc.name as NFDAPINF_CNTRLLRNM,
    case when nr.classname='UnifiedAp' then ipdns.managedaddress else null end as NFDAPINF_LLRIPADDRSS4,
    case when nr.classname='UnifiedAp' then nr.primaryMwar else null end as nfdApInf_primaryMwar,
    case when nr.classname='UnifiedAp' then nr.secondaryMwar else null end as nfdApInf_secondaryMwar,
    case when nr.classname='UnifiedAp' then nr.tertiaryMwar else null end as nfdApInf_tertiaryMwar,
    case when nr.classname='UnifiedAp' then nr.selectedCountryCode else null end as NFDAPINF_CONTRYCODE,
    case when nr.classname='UnifiedAp' and mei.managementaddress is not null then nr.lwappUpTime else null end
        as nfdApInf_capwapUpTime,
    case when nr.classname='UnifiedAp' then nr.lwappJoinTakenTime else null end as NFDAPINF_CPWPJNTKNTM,
    case when nr.classname='UnifiedAp' then nr.apWipsEnable else null end as nfdApInf_wIPSEnabled,
    case when nr.classname='UnifiedAp' then nr.switchPort else null end as nfdApInf_portNumber,
    case when nr.classname='UnifiedAp' then nr.statsCollectionInterval else null end as NFDAPINF_STTSTCSTMR,
    case when nr.classname='UnifiedAp' then nr.poeStatus else null end as nfdApInf_poeStatus,
    case when nr.classname='UnifiedAp' then (case when (nr.poeStatus between 1 and 7) then nr.poeStatus else 5 end)
        else null end as nfdApInf_poeStatusEnum,\
    case when nr.classname='UnifiedAp' then nr.rogueDetectionEnabled else null end as NFDAPINF_RGDTCTNENBLD,
    case when nr.classname='UnifiedAp' then nr.apEncryptionEnable else null end as nfdApInf_NCRYPTNENBLD,
    case when nr.classname='UnifiedAp' then nr.apTelnetStatus else null end as nfdApInf_telnetEnabled,
    case when nr.classname='UnifiedAp' then nr.apSSHStatus else null end as nfdApInf_sshEnabled,
    case when nr.classname='UnifiedAp' then nr.hreapofficeextendapen null null null null null null null N N N DEFINER 0 
'''
add_table(production, Table(
    'v4', 'data', 'AccessPointDetails', True, 8*HOUR, NUMAP,
    ('long', '@id'),                        # release 3.x changed string-->long
    ('String', '@displayName', None),       # dupl the @id uncommented 2018-07-01
    ('ApAdminStatusEnum', 'adminStatus'),
    ('String', 'apType'),                   # AP type
    # Ignore, because we don't/won't have any autonomous APs
    ('String', 'autonomousAP_description', False),  # SNMP sysDescr
    ('boolean', 'autonomousAP_reachable', False),  # SNMP reachable
    ('String', 'autonomousAP_sysLocation', False),  # SNMP sysLocation
    ('String', 'autonomousAP_sysObjectId', False),  # SNMP sysObjectId
    ('boolean', 'autonomousAP_wgbStatus', False),  # is the AP in WGB mode?
    ('int', 'clientCount'),                 # doc fixed string-->int in v4
    ('int', 'clientCount_2_4GHz'),          # doc fixed string-->int in v4
    ('int', 'clientCount_5GHz'),
    ('float', 'coordinates_XCoordinate'),   # x coordinate in feet
    ('float', 'coordinates_YCoordinate'),   # y coordinate in feet
    ('float', 'coordinates_ZCoordinate'),   # z coordinate in feet
    ('String', 'ethernetMac_octets'),       # AP MAC
    # ('String', 'instanceUuid'), 	        # blank. removed in v1
    ('String', 'ipAddress_address'),        # AP IP address
    ('String', 'locationHierarchy'),        # renamed from locationHeirarchy in v3
    ('String', 'macAddress_octets'),        # base radio MAC
    ('String', 'mapLocation'),              # SNMP location
    ('String', 'model'),                    # AP model
    ('String', 'name'),                     # AP name
    ('ReachabilityStateEnum', 'reachabilityStatus'),  # [not present]
    ('String', 'serialNumber'),
    ('long', 'serviceDomainId'),
    ('String', 'softwareVersion'),
    ('AlarmSeverityEnum', 'status'),
    ('String', 'type'),
    # have yet to see a populated unifiededApInfo
    # ('int', 'unifiedApInfo_instanceId'), 	# removed from all doc in v3
    # ('long', 'unifiedApInfo_instanceVersion'), 	# removed from all doc in v3
    ('smallint', 'unifiedApInfo_apCertType'),
    ('String', 'unifiedApInfo_apGroupName'),  # AP group this AP is assigned to
    ('MonitorOnlyModeEnum', 'unifiedApInfo_apMode'),  # doc as String but NUMBER through v2
    ('smallint', 'unifiedApInfo_apStaticEnabled'),
    ('String', 'unifiedApInfo_bootVersion'),  # Boot version
    ('long', 'unifiedApInfo_capwapJoinTakenTime'),  # 1/100ths to join CAPWAP
    ('long', 'unifiedApInfo_capwapUpTime'),  # 1/100ths since AP joined controller
    ('String', 'unifiedApInfo_controllerIpAddress'),
    ('String', 'unifiedApInfo_controllerName'),
    ('String', 'unifiedApInfo_contryCode'),  # 3-letter. misspelled in doc too
    ('boolean', 'unifiedApInfo_encryptionEnabled'),
    ('String', 'unifiedApInfo_flexConnectGroupName', False),  # [not present]
    ('boolean', 'unifiedApInfo_flexConnectMode'),
    ('String', 'unifiedApInfo_iosVersion'),
    ('Date', 'unifiedApInfo_lastAssociatedTime'),  # added vn ISO string
    ('Date', 'unifiedApInfo_lastDissociatedTime'),  # added vn ISO string
    ('boolean', 'unifiedApInfo_linkLatencyEnabled'),
    ('MeshRoleEnum', 'unifiedApInfo_lradMeshNode_meshRole'),  # added vn
    ('boolean', 'unifiedApInfo_maintenanceMode'),  # in maintenance mode?
    ('PoeStatusEnum', 'unifiedApInfo_poeStatusEnum'),  # [not present]
    ('smallint', 'unifiedApInfo_portNumber'),
    ('smallint', 'unifiedApInfo_powerInjectorState'),
    ('smallint', 'unifiedApInfo_preStandardState'),
    ('String', 'unifiedApInfo_primaryMwar'),
    ('boolean', 'unifiedApInfo_rogueDetectionEnabled'),
    ('String', 'unifiedApInfo_secondaryMwar'),
    ('boolean', 'unifiedApInfo_sshEnabled'),
    ('smallint', 'unifiedApInfo_statisticsTimer'),  # Stats interval in secs, or 0
    ('String', 'unifiedApInfo_tagInfo_policyTagName'),  # 20200814 receiving data
    ('String', 'unifiedApInfo_tagInfo_rfTagName'),  # 20200814 receiving data
    ('String', 'unifiedApInfo_tagInfo_siteTagName'),  # 20200814 receiving data
    ('UnifiedApTagSourceEnum', 'unifiedApInfo_tagInfo_tagSource', True),  # 202101 9800 controller
    ('boolean', 'unifiedApInfo_telnetEnabled'),
    ('String', 'unifiedApInfo_tertiaryMwar'),
    ('boolean', 'unifiedApInfo_vlanEnabled', False),  # not present-- no FlexConnect
    ('smallint', 'unifiedApInfo_vlanNativeId', False),
    ('boolean', 'unifiedApInfo_WIPSEnabled'),
    ('long', 'upTime'),  # AP up time in 1/100ths
)
          # entry per CDP neighbor
          .subTable('cdpNeighbors', [('float', 'polledTime'), ('long', '@id')],
                    ('String', 'capabilities'),
                    ('String', 'duplex'),   # Port mode {Half Duplex, Full Duplex}??
                    ('String', 'interfaceSpeed'),  # {10Mbps, 100Mbps, 1Gbps, 10Gbps, Auto}??
                    ('String', 'localPort'),  # local port number
                    ('String', 'neighborIpAddress_address'),
                    ('String', 'neighborName'),  # neighbor Device Name
                    ('String', 'neighborPort'),  # neighbor port number
                    ('String', 'platform')
                    )
          .subTable('reapApVlanAclMappings', [('float', 'polledTime'), ('long', '@id')],
                    ('String', 'reapEgressAcl', False),  # Egress ACL name for vlan-ACL mapping
                    ('String', 'reapIngressAcl', False),  # Ingress ACL name for vlan-ACL map
                    ('smallint', 'realVlanId', False)  # VLAN ID mapped to the ACL for this AP
                    )
          # array appeared after 2017-02-16 software upgrade
          .subTable('unifiedApInfo_wlanProfiles', [('float', 'polledTime'), ('long', '@id')],
                    ('boolean', 'broadcastSsidEnabled'),
                    ('String', 'profileName'),
                    ('String', 'ssid')
                    )
          .subTable('unifiedApInfo_wlanVlanMappings', [('float', 'polledTime'), ('long', '@id')],
                    ('String', 'ssid', False),  # WLAN SSID
                    ('smallint', 'vlanId', False),  # VLAN id
                    ('smallint', 'wlanId', False),  # WLAN id
                    )
          .set_id_field('@id')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )
'''
WCSDBA 	CLIENTCOUNTS
select cc.id as id, cc.type as type, case when cc.type=3 then sd.domainname else cc.key end as key,
cc.subkey as subkey, cc.eventTime as collectionTime, cc.totalassocount as count, cc.totalauthcount as authcount,
cc.protocolacount as dot11aCount, cc.protocolaauthcount as dot11aAuthCount, cc.protocolbcount as dot11bCount,
cc.protocolbauthcount as dot11bAuthCount, cc.protocolgcount as dot11gCount, cc.protocolgauthcount as dot11gAuthCount,
cc.protocoln24count as dot11n2_4Count, cc.protocoln24authcount as dot11n2_4AuthCount,
cc.protocoln5count as dot11n5Count, cc.protocoln5authcount as dot11n5AuthCount, cc.protocolaccount as dot11acCount,
cc.protocolacauthcount as dot11acAuthCount, cc.protocolax24count as dot11ax2_4Count,
cc.protocolax24authcount as dot11ax2_4AuthCount, cc.protocolax5count as dot11ax5Count,
cc.protocolax5authcount as dot11ax5AuthCount, cc.protocolwcount as wgbCount, cc.protocolwauthcount as wgbAuthCount,
cc.wiredSpeed10mCount as wired10MCount, cc.wiredSpeed10mAuthCount as wired10MAuthCount,
cc.wiredSpeed100mCount as wired100MCount, cc.wiredSpeed100mAuthCount as wired100MAuthCount,
cc.wiredSpeed1gCount as wired1GCount, cc.wiredSpeed1gAuthCount as wired1GAuthCount,
cc.wiredSpeed10gCount as wired10GCount, cc.wiredSpeed10gAuthCount as wired10GAuthCount
from ClientCount cc left outer join BaseServiceDomain sd on cast(sd.id as varchar(255))=cc.key
where type in (0,2,3,4,8,10) and cc.eventTime=(select max(eventTime) from ClientCount) 
'''
add_table(archive, Table(
    'v4', 'data', 'ClientCounts', True, 5*MINUTE, 120000,
    ('long', '@id'),
    ('String', '@displayName'),         # copy of @id uncommented 2018-07-01
    ('smallint', 'authCount'),          # as of last collection time
    ('epochMillis', 'collectionTime'),  # Epoch millis when record was collected
    ('smallint', 'count'),              # total client count
    ('smallint', 'dot11aAuthCount'),
    ('smallint', 'dot11aCount'),
    ('smallint', 'dot11acAuthCount'),
    ('smallint', 'dot11acCount'),
    ('smallint', 'dot11ax2_4AuthCount'),
    ('smallint', 'dot11ax2_4Count'),
    ('smallint', 'dot11ax5AuthCount'),
    ('smallint', 'dot11ax5Count'),
    ('smallint', 'dot11bAuthCount'),
    ('smallint', 'dot11bCount'),
    ('smallint', 'dot11gAuthCount'),
    ('smallint', 'dot11gCount'),
    ('smallint', 'dot11n2_4AuthCount'),
    ('smallint', 'dot11n2_4Count'),
    ('smallint', 'dot11n5AuthCount'),
    ('smallint', 'dot11n5Count'),
    # ('String', 'instanceUuid'),	# originally doc, but undoc from v1
    ('String', 'key'),
    ('String', 'subkey'),
    # for type=ACCESSPOINT; subkey is {'All', enum(SSIDs)}; key is an apMac
    # for type=DEVICE; subkey is {'All', enum(SSIDs)}; key is controller Ip
    # for type=MAPLOCATION; subkey is {'All', enum(SSIDs)}; key is a GroupSpecification.groupName
    # data is useless because e.g. 'Floor 1' is repeated w/o qualification
    # for type=SSID; subkey is {virtual domain, 'ROOT-DOMAIN'}; key is {'All SSIDs', enum(SSIDs)}
    # subkeys repeat multiple times. all data=0 except for ROOT-DOMAIN
    # for type=VIRTUALDOMAIN; subkey is All; key is virtualDomain [All Autonomous APs|All SSIDs|All wired|All Wireless]
    # similarly, the keys repeat multiple times, and all data=0 except for ROOT-DOMAIN - [|All Wireless|All SSIDs]
    ('ClientCountTypeEnum', 'type'),
    ('smallint', 'wgbAuthCount'),   # clients auth as WGB or wired guest
    ('smallint', 'wgbCount'),       # clients connected as WorkGroup Bridge or wired guest
    ('smallint', 'wired100MAuthCount'),
    ('smallint', 'wired100MCount'),
    ('smallint', 'wired10GAuthCount', False),  # appeared in 3.6
    ('smallint', 'wired10GCount', False),  # appeared in 3.6
    ('smallint', 'wired10MAuthCount'),
    ('smallint', 'wired10MCount'),
    ('smallint', 'wired1GAuthCount'),
    ('smallint', 'wired1GCount')
    # ('String', 'adminStatus')		# undoc field appeared in 2017-02-16, then undoc
).set_id_field('@id').set_time_field('collectionTime')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )
'''
WCSDBA 	CLIENTDETAILS
select bs.macAddress, bs.ipType,
    replace(case bs.ipType when 0 then bs.ipAddress when 2 then bs.ipAddress when 1 then ipv6.ipAddress end, ' ', '')
        as ipAddress,
    bs.id, bs.username, bs.authEntityId, bs.authEntityClass, bs.connectionType, bs.clientVendor as vendor,
    bs.deviceType, bs.switchName as deviceName, ipdns.managedaddress as deviceIpAddress, bs.heirarchyName as location,
    bs.hostname, bs.ssId, bs.clientVlanId as vlan, bs.clientVlanName as vlanName, bs.status, bs.clientInterface,
    bs.protocol, bs.lastSessionTime as associationTime, bs.updateTime, bs.firstSeen as firstSeenTime, bs.policyType,
    bs.eapType, bs.securitypolicystatus, bs.websecurity, bs.failurecode, bs.failurestep, bs.authorizationpolicy,
    bs.radiusresponse, bs.authntimestamp, bs.auditsessionid, bs.posturestatus, bs.ctssecuritygroup, bs.iseName,
    bs.addomainname, bs.mobilityStatus, bs.lradname as apName, bs.lradifslotid as apSlotId,
    bs.lradmacaddr as apMacAddress, replace(bs.lradipaddress, ' ', '') as apIpAddress, bs.authenticationalgorithm,
    bs.wepstate, bs.clientapmode, bs.encryptioncypher, bs.wgbstatus, bs.wgbmacaddress, bs.ccxversion,
    bs.ccxfsversion, bs.ccxlsversion, bs.ccxmsversion, bs.ccxvsversion, bs.nacState, bs.hreaplocallyauthenticated,
    bs.wiredClientType, bs.clientaclapplied, bs.clientaclname, bs.clientaaaoverrideaclapplied,
    bs.clientaaaoverrideaclname, bs.clientRedirectUrl, bs.ifIndex, bs.ifDescr, bs.speed, bs.policyTypeStatus,
    bs.authorizedby, coalesce(ci.throughput, bs.throughput, 0) as throughput,
    coalesce(ci.bytesSent, bs.bytesSent, 0) as bytesSent,
    coalesce(ci.bytesReceived, bs.bytesReceived, 0) as bytesReceived,
    coalesce(ci.packetsSent, 0) as packetsSent, coalesce(ci.packetsReceived, 0) as packetsReceived,
    case when (bs.connectionType = 2) or (bs.connectionType = 0 and bs.protocol = 8) then -128
        else coalesce(ci.rssi, bs.rssi, -128) end as rssi,
    coalesce(ci.snr, bs.snr, 0) as snr,
    coalesce(ci.bytesSent, bs.bytesSent, 0) + coalesce(ci.bytesReceived, bs.bytesReceived, 0) as traffic
from baseStation bs left join (
    select macAddress, ipAddress, ipAddressT, ROW_NUMBER() OVER (
        PARTITION BY macAddress ORDER BY ipAddressScope, discoverTime desc, idx asc) as rowNumber
    from vwStationIPAddress
    where discoverTime is not null and ipAddressT in (2, 4)
        and ipAddress is not null and ipAddress != 'NULL_VALUE') ipv6
    on bs.macAddress = ipv6.macAddress and ipv6.rowNumber = 1
    left join ClientSessionInfo ci on ci.clientMacAddress = bs.macAddress and ci.sessionStartTime = bs.lastSessionTime
    left join networkresource res on res.id = bs.parentid
    left join managedelementinterface mei on mei.id = res.managedelementinterface_id
    left join ipaddresstodnsmapping ipdns on ipdns.mapping_id = mei.id
'''
# Poll daily for details e.g {ccx*} not in ClientSessions or HistoricalClient*
offset += 5*60.0
# One record for each client seen per updateTime within the last week
add_table(production, Table(
    'v4', 'data', 'ClientDetails', True, DAY + offset, 60000,
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),   # dupl the @id uncommented 2018-07-01
    ('String', 'adDomainName', False),  # AD domain acquired from ISE
    ('String', 'apIpAddress_address'),  # associated AP IP address
    ('String', 'apMacAddress_octets'),  # associated AP MAC address
    ('String', 'apName'),               # associated AP name
    ('smallint', 'apSlotId'),           # associated AP slot ID
    ('epochMillis', 'associationTime'),  # current or last session start
    ('String', 'auditSessionId', False),  # Client audit session ID
    ('AuthenticationAlgorithmEnum', 'authenticationAlgorithm'),  # client's auth.
    ('String', 'authnTimeStamp', False),  # acquired from ISE
    ('String', 'authorizationPolicy'),  # acquired from ISE. 7/2021 ISE populating
    ('String', 'authorizedBy', False),  # Authorization provider
    # ('long', 'bytesReceived'),	    # only present in v1
    # ('long', 'bytesSent'),   			# only present in v1
    ('CcxFSVersionEnum', 'ccxFSVersion'),  # client card version
    ('CcxFSVersionEnum', 'ccxLSVersion'),  # client card version
    ('CcxFSVersionEnum', 'ccxMSVersion'),  # client card version
    ('CcxFSVersionEnum', 'ccxVSVersion'),  # client card version
    ('CCXVersionEnum', 'ccxVersion'),   # client card version
    ('ClientAclAppliedEnum', 'clientAaaOverrideAclApplied'),  # override applied?
    ('String', 'clientAaaOverrideAclName', False),  # ACL name
    ('ClientAclAppliedEnum', 'clientAclApplied'),  # ACL applied to client
    ('String', 'clientAclName', False),  # ACL name applied to the client
    ('ClientApModeEnum', 'clientApMode'),
    ('String', 'clientInterface'),      # interface LAN
    ('String', 'clientRedirectUrl', False),  # Redirect URL applied to the client
    ('ConnectionTypeEnum', 'connectionType'),  # from ISE
    ('String', 'ctsSecurityGroup'),     # 7/2021 populated occasionally
    ('String', 'deviceIpAddress_address'),  # of associated controller or switch
    ('String', 'deviceName'),           # name of associated controller or switch
    ('String', 'deviceType'),           # Client device type acquired from ISE
    ('EapTypeEnum', 'eapType'),
    ('EncryptionCypherEnum', 'encryptionCypher'),  # Client encrpyt. cypher
    ('String', 'failureCode'),          # from ISE. 7/2021 ISE populating
    ('String', 'failureStep', False),   # from ISE
    ('epochMillis', 'firstSeenTime'),   # time when client was first discovered
    ('String', 'hostname', False),      # reverse DNS from client IP address
    ('HreapAuthenticationEnum', 'hreapLocallyAuthenticated'),  # auth via HREAP?
    ('String', 'ifDescr', False),       # SNMP ifDescr of the connected switch
    ('int', 'ifIndex'),                 # SNMP ifIndex of the connected switch
    # ('String', 'instanceUUid'),		# not in the doc., but present in v2.
    ('String', 'ipAddress_address'),    # Client IP address
    ('ClientIpTypeEnum', 'ipType'),     # Client IP type
    ('String', 'iseName'),  # ISE name which the client is reported. 7/2021 ISE populating
    ('String', 'location'),             # Map location hierarchy
    ('String', 'macAddress_octets'),    # Client MAC address
    ('MobilityStatusEnum', 'mobilityStatus'),  # Client mobility status
    ('NACStateEnum', 'nacState'),       # Client NAC state
    # ('long', 'packetsReceived'), 		# only in v1
    # ('long', 'packetsSent'),			# only in v1
    ('SecurityPolicyEnum', 'policyType'),  # v2
    ('PolicyTypeStatusEnum', 'policyTypeStatus'),  # Client from ISE
    ('PostureStatusEnum', 'postureStatus'),  # Client from ISE
    ('ClientProtocolEnum', 'protocol'),  # [last] connection protocol
    ('String', 'radiusResponse', False),  # from ISE
    # ('smallint', 'rssi'),				# only in v1
    ('SecurityPolicyStatusEnum', 'securityPolicyStatus'),  # Client on network?
    # ('smallint', 'snr'),				# only in v1
    ('ClientSpeedEnum', 'speed'),       # wired port speed or UNKNOWN for wireless
    ('String', 'ssid'),  # [last] SSID
    ('ClientStatusEnum', 'status'),     # Client connection
    # ('double', 'throughput'),			# only in v1
    # ('long', 'traffic'),				# only in v1
    ('epochMillis', 'updateTime'),      # time this record was last updated
    ('String', 'userName'),             # Client username
    ('String', 'vendor'),           # Vendor name of the client NIC from OUI mapping
    ('smallint', 'vlan'),  # VLAN ID. JSON is NUMBER. Doc corrected string-->int in v4
    ('String', 'vlanName'),         # client's VLAN; blank < 202101 9800 controller
    ('WebSecurityEnum', 'webSecurity'),  # client is authenticated by WebAuth
    ('WepStateEnum', 'wepState'),
    ('String', 'wgbMacAddress_octets'),  # if client s a WorkGroup Bridge
    ('WGBStatusEnum', 'wgbStatus'),     # Client WorkGroup Bridge status
    ('WiredClientTypeEnum', 'wiredClientType')
)
          .subTable('clientAddresses', [('float', 'polledTime'), ('long', '@id')],
                    ('ClientIpAddressAssignmentType', 'assignmentType', False),
                    ('Date', 'discoverTime', False),  # client discovery time
                    ('String', 'ipAddress_address', False),
                    ('ClientIpAddressScope', 'ipAddressScope', False),
                    ('String', 'macAddress_octets', False)
                    )
          .set_id_field('@id')
          .set_time_field('updateTime')
          # .set_generator(real_timeGen)
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )

# One record for each client seen per updateTime within the last week
# ClientSessionsDetails uses this table as a template
add_table(archive, Table(
    'v4', 'data', 'ClientDetails', True, 4*60, 60000,
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),   # dupl the @id uncommented 2018-07-01
    ('String', 'adDomainName', False),  # AD domain acquired from ISE
    ('String', 'apIpAddress_address', False),  # associated AP IP address
    ('String', 'apMacAddress_octets'),  # associated AP MAC address
    ('String', 'apName'),               # associated AP name
    ('smallint', 'apSlotId'),           # associated AP slot ID
    ('epochMillis', 'associationTime'),  # current or last session start
    ('String', 'auditSessionId', False),  # Client audit session ID
    ('AuthenticationAlgorithmEnum', 'authenticationAlgorithm'),  # client's auth.
    ('String', 'authnTimeStamp', False),  # acquired from ISE
    ('String', 'authorizationPolicy', False),  # acquired from ISE
    ('String', 'authorizedBy', False),  # Authorization provider
    # ('long', 'bytesReceived'),		# only present in v1
    # ('long', 'bytesSent'),   			# only present in v1
    ('CcxFSVersionEnum', 'ccxFSVersion', False),  # client card version
    ('CcxFSVersionEnum', 'ccxLSVersion', False),  # client card version
    ('CcxFSVersionEnum', 'ccxMSVersion', False),  # client card version
    ('CcxFSVersionEnum', 'ccxVSVersion', False),  # client card version
    ('CCXVersionEnum', 'ccxVersion', False),  # client card version
    ('ClientAclAppliedEnum', 'clientAaaOverrideAclApplied', False),
    ('String', 'clientAaaOverrideAclName', False),  # ACL name
    ('ClientAclAppliedEnum', 'clientAclApplied'),  # ACL applied to client
    ('String', 'clientAclName', False),  # ACL name applied to the client
    ('ClientApModeEnum', 'clientApMode'),
    ('String', 'clientInterface'),      # interface LAN
    ('String', 'clientRedirectUrl', False),  # Redirect URL applied to the client
    ('ConnectionTypeEnum', 'connectionType'),  # from ISE
    ('String', 'ctsSecurityGroup', False),
    ('String', 'deviceIpAddress_address', False),  # of assoc. controller or switch
    ('String', 'deviceName', False),    # name of associated controller or switch
    ('String', 'deviceType'),           # Client device type acquired from ISE
    ('EapTypeEnum', 'eapType'),
    ('EncryptionCypherEnum', 'encryptionCypher'),  # Client encrpyt. cypher
    ('String', 'failureCode', False),   # from ISE
    ('String', 'failureStep', False),   # from ISE
    ('epochMillis', 'firstSeenTime', False),  # when client was first discovered
    ('String', 'hostname', False),      # reverse DNS from client IP address
    ('HreapAuthenticationEnum', 'hreapLocallyAuthenticated'),  # auth via HREAP?
    ('String', 'ifDescr', False),       # SNMP ifDescr of the connected switch
    ('int', 'ifIndex', False),          # SNMP ifIndex of the connected switch
    # ('String', 'instanceUUid'),		# not in the doc., but present in v2.
    ('String', 'ipAddress_address'),    # Client IP address
    ('ClientIpTypeEnum', 'ipType'),     # Client IP type
    ('String', 'iseName', False),       # ISE name which the client is reported
    ('String', 'location', False),      # Map location hierarchy
    ('String', 'macAddress_octets'),    # Client MAC address
    ('MobilityStatusEnum', 'mobilityStatus'),  # Client mobility status
    ('NACStateEnum', 'nacState'),       # Client NAC state
    # ('long', 'packetsReceived'), 		# only in v1
    # ('long', 'packetsSent'),			# only in v1
    ('SecurityPolicyEnum', 'policyType'),  # v2
    ('PolicyTypeStatusEnum', 'policyTypeStatus'),  # Client from ISE
    ('PostureStatusEnum', 'postureStatus'),  # Client from ISE
    ('ClientProtocolEnum', 'protocol'),  # [last] connection protocol
    ('String', 'radiusResponse', False),  # from ISE
    # ('smallint', 'rssi'),				# only in v1
    ('SecurityPolicyStatusEnum', 'securityPolicyStatus'),  # Client on network?
    # ('smallint', 'snr'),				# only in v1
    ('ClientSpeedEnum', 'speed', False),  # wired port speed or UNKNOWN for wireless
    ('String', 'ssid'),  # [last] SSID
    ('ClientStatusEnum', 'status'),  # Client connection
    # ('double', 'throughput'),			# only in v1
    # ('long', 'traffic'),				# only in v1
    ('epochMillis', 'updateTime'),      # time this record was last updated
    ('String', 'userName'),             # Client username
    ('String', 'vendor', False),        # Vendor name of the client NIC from OUI mapping
    ('smallint', 'vlan'),   # VLAN ID. JSON is NUMBER. Doc corrected string-->int in v4
    ('String', 'vlanName', False),      # [blank] that client is connected to
    ('WebSecurityEnum', 'webSecurity'),  # client is authenticated by WebAuth
    ('WepStateEnum', 'wepState'),
    ('String', 'wgbMacAddress_octets', False),  # if client s a WorkGroup Bridge
    ('WGBStatusEnum', 'wgbStatus', False),  # Client WorkGroup Bridge status
    ('WiredClientTypeEnum', 'wiredClientType', False)
)
          .subTable('clientAddresses', [('float', 'polledTime'), ('long', '@id')],
                    ('ClientIpAddressAssignmentType', 'assignmentType', False),
                    ('Date', 'discoverTime', False),  # client discovery time
                    ('String', 'ipAddress_address', False),
                    ('ClientIpAddressScope', 'ipAddressScope', False),
                    ('String', 'macAddress_octets', False)
                    )
          .set_id_field('@id')
          .set_time_field('updateTime')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )

""" This view is SELECT CS.*, CD,.apSlotId, CD.updateTime
from ClientSessions CS, ClientDetails, CD
where CS.macAddress_octets=CD.macAddress_octets
    and CS.sessionStartTime=CD.associationTime.
It verifies matching fields are equal and reports suspect/failures-to match.
"""
add_table(real_time, Table(
    'v4', 'data', 'ClientSessionsDetails', True, 298, 17000,
    ('long', '@id'),  # release 3.x changed string-->long
    ('String', '@displayName', None),  # copy of @id
    ('String', 'adDomainName', None),  # from ISE; missing in v2 and v4
    ('String', 'anchorIpAddress_address', None),  # of mobility anchor, or 0.0.0.0
    # ('String', 'apIpAddress'),		# doc but blank in v1. removed in v3
    ('String', 'apMacAddress_octets'),  # MAC of associated AP
    # ('String', 'apName'),			    # was blank in v1. removed in v3
    ('smallint', 'apSlotId'),           # associated AP slot ID (from ClientDetails)
    ('AuthenticationAlgorithmEnum', 'authenticationAlgorithm', None),  # Client alg
    ('String', 'authorizationPolicy', None),  # from ISE; missing in v1 and v4
    ('long', 'bytesReceived'),          # bytes received [so far] during the session
    ('long', 'bytesSent'),              # bytes sent [so far] during the session
    ('String', 'clientInterface', None),  # {case[auth|guest]*, ic-inside, management}
    ('ConnectionTypeEnum', 'connectionType', None),
    ('String', 'ctsSecurityGroup', None),  # from ISE; missing in v2 and v4
    ('String', 'deviceMgmtAddress_address', None),
    # controller. v3 changed string --> InetAddress
    ('String', 'deviceName', None),     # controller or switch name
    ('EapTypeEnum', 'eapType', None),
    ('EncryptionCypherEnum', 'encryptionCypher', None),  # Client cypher
    # ('String', 'instanceUuid'),		# originally doc, but removed in v1
    ('String', 'ipAddress_address', None),  # Client. str in v1, InetAddress in v3
    ('ClientIpTypeEnum', 'ipType', None),
    ('String', 'location', None),       # Map: campus > building > floor
    ('String', 'macAddress_octets'),    # Client MAC
    ('long', 'packetsReceived'),        # number received [so far] in the session
    ('long', 'packetsSent'),            # number sent [so far] in the session
    ('PolicyTypeStatusEnum', 'policyTypeStatus', None),  # Client policy
    ('ClientSpeedEnum', 'portSpeed', None),  # Speed for wired; UNKNOWN for wireless
    ('PostureStatusEnum', 'postureStatus', None),  # Client posture from ISE
    ('String', 'profileName'),          # WLAN Profile Name
    ('ClientProtocolEnum', 'protocol'),
    ('String', 'roamReason', None),     # missing in v1 and v4
    ('smallint', 'rssi'),               # dBm from last polling in the session
    ('SecurityPolicyEnum', 'securityPolicy', None),  # Client policy
    ('epochMillis', 'sessionEndTime'),  # session end time; or far future time
    ('epochMillis', 'sessionStartTime'),
    ('smallint', 'snr'),                # Signal to Noise Ratio from last polling
    ('String', 'ssid'),                 # SSID
    ('double', 'throughput', None),     # Session avg. blank while session open
    ('epochMillis', 'updateTime'),      # record last updated (from ClientDetails)
    ('String', 'userName'),             # Client username
    ('smallint', 'vlan', None),         # vlan name. was string before v3
    ('WebSecurityEnum', 'webSecurity', None),  # is Client auth via WebAuth?
    ('String', 'wgbMacAddress_octets', None),  # WorkGroup Bridge MAC or '00:00:00:00:00:00:00'
    ('WGBStatusEnum', 'wgbStatus', None),  # Client type
).set_id_field('@id')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          .set_generator(real_timeCS)
          )
'''
WCSDBA 	CLIENTSESSIONS
select cs.id as id, cs.clientMacAddress as macAddress, cs.clientUserName as userName,
replace(cs.clientIpAddress,' ','') as ipAddress, cs.authEntityClass as authEntityClass, cs.authEntityId as authEntityId,
cs.sessionStartTime as sessionStartTime, cs.sessionEndTime as sessionEndTime, cs.connectionType as connectionType,
cs.deviceName as deviceName, ipdns.managedaddress as deviceIpAddress,
replace(cs.anchorControllerIpAddress,' ','') as anchorIpAddress, cs.associatedAp as apMacAddress,
replace(ap.ipAddress_address,' ','') as apIpAddress, ap.lradName as apName, cs.location as location,
cs.ssid as ssid, cs.profileName as profileName, cs.clientVlanId as vlan, cs.clientInterface as clientInterface,
cs.protocol as protocol, cs.speed as portSpeed, cs.roamReason as roamReason,
cs.authenticationAlgorithm as authenticationAlgorithm, cs.policytype as securityPolicy,
cs.policyTypeStatus as policyTypeStatus, cs.encryptionCypher as encryptionCypher, cs.eapType as eapType,
cs.webSecurity as webSecurity, cs.wgbMacAddress as wgbMacAddress, cs.wgbStatus as wgbStatus,
cs.throughput as throughput, cs.bytesSent as bytesSent, cs.bytesReceived as bytesReceived,
cs.packetsSent as packetsSent, cs.packetsReceived as packetsReceived, cs.snr as snr, cs.rssi as rssi,
cs.authorizationPolicy as authorizationPolicy, cs.postureStatus as postureStatus,
cs.ctsSecurityGroup as ctsSecurityGroup, cs.adDomainName as adDomainName, cs.ipType as ipType
from ClientSessionInfo cs left outer join WirelessAccessPoint ap on ap.macAddress=cs.associatedAP
    left outer join managedelementinterface mei on mei.PADDEDMGMTADDRESS = cs.DEVICEIPADDRESS
    left join ipaddresstodnsmapping ipdns on ipdns.mapping_id = mei.id
'''
''' One record per session that ended in the past 4 weeks or is currently active
The system regularly updates the data in each active session. When a
session is active, its sessionEndTime is set to a time far in the future.
Once a session is closed, the record is frozen, with its actual sessionEndTime.
'''
'''differences from ClientSessions to ClientDetails
+apIpAddress        MOOT because have apMacAddress
+apName             MOOT because have apMacAddress
+apSlotId           NICE TO HAVE to identify slot
+associationTime    DON'T NEED
+auditSessionId     DON'T NEED
+authnTimeStamp     DON'T NEED
+authorizedBy       DON'T NEED
-bytesReceived      NICE TO HAVE
-bytesSent          NICE TO HAVE
+ccxFSVersion, ccxLSVersion, ccxMSVersion, ccxVSVersion, ccxVersion     DON'T NEED
+clientAaaOverrideAclApplied, clientAaaOverrideAclName, clientAclApplied, clientAclName DON'T NEED
+clientApMode       DON'T NEED
+clientRedirectUrl  DON'T NEED
+deviceIpAddress_address, -deviceMgmtAddress_address
+deviceType         NICE TO HAVE
+failureCode, failureStep, firstSeenTime, hostname, hreapLocallyAuthenticated   DON'T NEED
+ifDescr, ifIndex   DON'T NEED
+iseName            DON'T NEED
+mobilityStatus, nacState   DON'T NEED
-packetsReceived, packetsSent   NICE TO HAVE
+policyType         DON'T NEED
-portSpeed +speed
-profileName        DON'T NEED. Both have ssid
+radiusResponse     DON'T NEED
-rssi               NICE TO HAVE
+securityPolicyStatus - securityPolicy
-sessionEndTime, sessionStartTime
-snr                NICE TO HAVE
+status             MINOR
-throughput         NICE TO HAVE
+updateTime         Infer from polledTime
+vendor             NICE TO HAVE
+vlanName           blank. However both have vlan
+wiredClientType, clientAddresses(assignmentType, discoverTime, ipAddress_address,
                            ipAddressScope, macAddress_octets) DON'T NEED

'''
add_table(production, Table(
    'v4', 'data', 'ClientSessions', False, 21*HOUR, 17000,
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),   # copy of @id
    ('String', 'adDomainName', False),  # from ISE; missing in v2 and v4
    ('String', 'anchorIpAddress_address'),  # of the mobility anchor, or 0.0.0.0
    # ('String', 'apIpAddress'),		# doc but blank in v1. removed in v3
    ('String', 'apMacAddress_octets'),  # MAC of associated AP
    # ('String', 'apName'),			    # was blank in v1. removed in v3
    ('AuthenticationAlgorithmEnum', 'authenticationAlgorithm'),  # Client alg
    ('String', 'authorizationPolicy'),  # from ISE; missing in v1 and v4. 7/2021 populated
    ('long', 'bytesReceived'),          # bytes received [so far] during the session
    ('long', 'bytesSent'),              # bytes sent [so far] during the session
    ('String', 'clientInterface'),      # {case[auth|guest]*, ic-inside, management}
    ('ConnectionTypeEnum', 'connectionType'),
    ('String', 'ctsSecurityGroup', False),  # from ISE; missing in v2 and v4
    ('String', 'deviceMgmtAddress_address'),  # controller. v3 string --> InetAddress
    ('String', 'deviceName'),           # controller or switch name
    ('EapTypeEnum', 'eapType'),
    ('EncryptionCypherEnum', 'encryptionCypher'),  # Client cypher
    # ('String', 'instanceUuid'),		# originally doc, but removed in v1
    ('String', 'ipAddress_address'),    # Client. string in v1, InetAddress in v3
    ('ClientIpTypeEnum', 'ipType'),
    ('String', 'location'),             # AP or switch Map: campus > building > floor
    ('String', 'macAddress_octets'),    # Client MAC
    ('long', 'packetsReceived'),        # number received [so far] in the session
    ('long', 'packetsSent'),            # number sent [so far] in the session
    ('PolicyTypeStatusEnum', 'policyTypeStatus'),  # Client policy
    ('ClientSpeedEnum', 'portSpeed'),   # Speed for wired or UNKNOWN for wireless
    ('PostureStatusEnum', 'postureStatus'),  # Client posture from ISE
    ('String', 'profileName'),          # WLAN Profile Name
    ('ClientProtocolEnum', 'protocol'),
    ('String', 'roamReason', False),    # missing in v1 and v4
    ('smallint', 'rssi'),               # dBm from last polling in the session
    ('SecurityPolicyEnum', 'securityPolicy'),  # Client policy
    ('epochMillis', 'sessionEndTime'),  # session end time; or far future time
    # in some cases the sessionEndTime not synchronized to the 5-minute polling
    ('epochMillis', 'sessionStartTime'),
    ('smallint', 'snr'),                # Signal to Noise Ratio from last polling
    ('String', 'ssid'),                 # SSID
    ('double', 'throughput'),           # Session avg. blank while session open
    ('String', 'userName'),             # Client username
    ('smallint', 'vlan'),               # vlan name. was string before v3
    ('WebSecurityEnum', 'webSecurity'),  # is Client auth via WebAuth?
    ('String', 'wgbMacAddress_octets'),  # WorkGroup Bridge MAC or '00:00:00:00:00:00:00'
    ('WGBStatusEnum', 'wgbStatus'),     # Client type
).set_id_field('@id').set_time_field('sessionStartTime').set_rollup(28*DAY)
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          .set_pager('cs_pager')
          )

'''WCSDBA 	CLIENTSTATS
select cs.id as id, cs.macAddress as macAddress, cs.eventTime as collectionTime, cs.rssi as rssi, cs.snr as snr,
cs.bytesReceived as bytesReceived, cs.bytesSent as bytesSent, cs.packetsReceived as packetsReceived,
cs.packetsSent as packetsSent, cs.dataRate as dataRate, cs.raPacketsDropped as raPacketsDropped,
cs.clientDataRetries as dataRetries, cs.clientRtsRetries as rtsRetries, cs.txBytesDropped as txBytesDropped,
cs.rxBytesDropped as rxBytesDropped, cs.txPacketsDropped as txPacketsDropped, cs.rxPacketsDropped as rxPacketsDropped
from ( select StationInfo.*, row_number() over (partition by macAddress order by eventTime desc) as rank
    from StationInfo where eventTime >= (select max(eventTime) - 1 * 60 * 60 * 1000 from StationInfo) ) cs
where cs.rank = 1
'''
# Cumulative (bytes, packets) x (sent, received, dropped|retries) by client MAC
# Active sessions posted every 15 minutes. Deleted after 24 hours
# statistics are during this session
add_table(archive, Table(
    'v4', 'data', 'ClientStats', True, 6*MINUTE, 36000,
    ('long', '@id'),                    # Session id. release 3.x changed string-->long
    ('String', '@displayName', None),   # copy of @id uncommented 2018-07-01
    ('long', 'bytesReceived'),          # cumulative bytes received
    ('long', 'bytesSent'),              # cumulative bytes sent
    ('epochMillis', 'collectionTime'),  # Unix epoch millis
    ('float', 'dataRate'),              # reading data rate Mbps
    ('long', 'dataRetries'),            # cumulative data Retries
    # ('String', 'instanceUuid'),	    # originally doc. removed in v1
    ('String', 'macAddress_octets'),    # client MAC
    ('long', 'packetsReceived'),        # cumulative packets received
    ('long', 'packetsSent'),            # cumulative packets Sent
    ('long', 'raPacketsDropped'),       # cumulative IPv6 RA packets dropped
    ('smallint', 'rssi'),               # RSSI (dBm) as measured by AP
    ('long', 'rtsRetries'),             # cumulative RTS Retries
    ('long', 'rxBytesDropped'),         # cumulative rx Bytes dropped
    ('long', 'rxPacketsDropped'),       # cumulative rx Packets dropped
    ('smallint', 'snr'),                # SNR as measured by the AP
    ('long', 'txBytesDropped'),         # cumulative tx Bytes dropped
    ('long', 'txPacketsDropped')        # cumulative tx Packets dropped
).set_id_field('@id').set_time_field('collectionTime')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )

'''WCSDBA 	CLIENTTRAFFICS
select ct.id as id, ct.type as type, case when ct.type=3 then sd.domainname else ct.key end as key,
    ct.subkey as subkey, ct.eventTime as collectionTime,
    ct.protocolaSent+ct.protocolbSent+ct.protocolgSent+ct.protocoln24Sent+ct.protocoln5Sent+ct.protocolacSent
        + ct.protocolax24Sent+ct.protocolax5Sent+ct.wiredspeed10mSent+ct.wiredspeed100mSent+ct.wiredspeed1gSent
        +ct.wiredspeed10gSent as sent,
    ct.protocolaReceived+ct.protocolbReceived+ct.protocolgReceived+ct.protocoln24Received+ct.protocoln5Received
        +ct.protocolacReceived+ ct.protocolax24Received+ct.protocolax5Received+ct.wiredspeed10mReceived
        +ct.wiredspeed100mReceived+ct.wiredspeed1gReceived+ct.wiredspeed10gReceived as received,
    ct.protocolaThroughput+ct.protocolbThroughput+ct.protocolgThroughput+ct.protocoln24Throughput
        +ct.protocoln5Throughput+ct.protocolacThroughput+ ct.protocolax24Throughput+ct.protocolax5Throughput
        +ct.wiredspeed10mThroughput+ct.wiredspeed100mThroughput+ct.wiredspeed1gThroughput
        +ct.wiredspeed10gThroughput as throughput,
    ct.protocolaSent as dot11aSent, ct.protocolaReceived as dot11aReceived, ct.protocolaThroughput as dot11aThroughput,
    ct.protocolbSent as dot11bSent, ct.protocolbReceived as dot11bReceived, ct.protocolbThroughput as dot11bThroughput,
    ct.protocolgSent as dot11gSent, ct.protocolgReceived as dot11gReceived, ct.protocolgThroughput as dot11gThroughput,
    ct.protocoln24Sent as dot11n2_4Sent, ct.protocoln24Received as dot11n2_4Received,
    ct.protocoln24Throughput as dot11n2_4Throughput, ct.protocoln5Sent as dot11n5Sent,
    ct.protocoln5Received as dot11n5Received, ct.protocoln5Throughput as dot11n5Throughput,
    ct.protocolacSent as dot11acSent, ct.protocolacReceived as dot11acReceived,
    ct.protocolacThroughput as dot11acThroughput, ct.protocolax24Sent as dot11ax2_4Sent,
    ct.protocolax24Received as dot11ax2_4Received, ct.protocolax24Throughput as dot11ax2_4Throughput,
    ct.protocolax5Sent as dot11ax5Sent, ct.protocolax5Received as dot11ax5Received,
    ct.protocolax5Throughput as dot11ax5Throughput, ct.wiredSpeed10mSent as wired10MSent,
    ct.wiredSpeed10mReceived as wired10MReceived, ct.wiredSpeed10mThroughput as wired10MThroughput,
    ct.wiredSpeed100mSent as wired100MSent, ct.wiredSpeed100mReceived as wired100MReceived,
    ct.wiredSpeed100mThroughput as wired100MThroughput, ct.wiredSpeed1gSent as wired1GSent,
    ct.wiredSpeed1gReceived as wired1GReceived, ct.wiredSpeed1gThroughput as wired1GThroughput,
    ct.wiredSpeed10gSent as wired10GSent, ct.wiredSpeed10gReceived as wired10GReceived,
    ct.wiredSpeed10gThroughput as wired10GThroughput
from ClientTraffic ct left outer join BaseServiceDomain sd on cast(sd.id as varchar(255))=ct.key
where type in (0,2,3,4,8,10) and ct.eventTime=(select max(eventTime) from ClientTraffic)
'''
# Cumulative (Received,Sent,Throughput) x (a,ac,d,g,n2.4,5,...) by element[Key+Type]
# Posted every 15 minutes
add_table(archive, Table(
    'v4', 'data', 'ClientTraffics', True, 5*MINUTE, int(NUMHIST*SAMPERHR),
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),   # copy of @id uncommented 2018-07-01
    # ('String', '@uuid'),			    # removed from documentation in v1+
    ('epochMillis', 'collectionTime'),
    ('long', 'dot11aReceived'),         # cumulative bytes received
    ('long', 'dot11aSent'),             # cumulative bytes sent
    ('long', 'dot11aThroughput'),       # cumulative throughput in Kbps
    ('long', 'dot11acReceived'),        # cumulative bytes received
    ('long', 'dot11acSent'),            # cumulative bytes sent
    ('long', 'dot11acThroughput'),      # total throughput in Kbps
    ('long', 'dot11ax2_4Received'),     # cumulative bytes received
    ('long', 'dot11ax2_4Sent'),         # cumulative bytes sent
    ('long', 'dot11ax2_4Throughput'),   # total throughput in Kbps
    ('long', 'dot11ax5Received'),       # cumulative bytes received
    ('long', 'dot11ax5Sent'),           # cumulative bytes sent
    ('long', 'dot11ax5Throughput'),     # total throughput in Kbps
    ('long', 'dot11bReceived'),         # cumulative bytes received
    ('long', 'dot11bSent'),             # cumulative bytes sent
    ('long', 'dot11bThroughput'),       # total throughput in Kbps
    ('long', 'dot11gReceived'),         # cumulative bytes received
    ('long', 'dot11gSent'),             # cumulative bytes sent
    ('long', 'dot11gThroughput'),       # total throughput in Kbps
    ('long', 'dot11n2_4Received'),      # cumulative bytes received
    ('long', 'dot11n2_4Sent'),          # cumulative bytes sent
    ('long', 'dot11n2_4Throughput'),    # total throughput in Kbps
    ('long', 'dot11n5Received'),        # cumulative bytes received
    ('long', 'dot11n5Sent'),            # cumulative bytes sent
    ('long', 'dot11n5Throughput'),      # cumulative throughput in Kbps
    # ('String', 'instanceUuid'),	    # originally doc. removed in v1.x
    ('String', 'key'),      # byType {MAC, IP address, 'All Guest', text, SSID, text}
    ('long', 'received'),               # total bytes received
    ('long', 'sent'),                   # total bytes sent
    ('String', 'subkey'),               # depends on type:
    # for type=ACCESSPOINT; subkey is {'All', enum(SSIDs)}; key is an apMac
    # for type=DEVICE; subkey is {'All', enum(SSIDs)}; key is controller Ip
    # for type=MAPLOCATION; subkey is {'All', enum(SSIDs)}; key is a GroupSpecification.groupName
    # data is useless because e.g. 'Floor 1' is repeated w/o qualification
    # for type=SSID; subkey is {virtual domain, 'ROOT-DOMAIN'}; key is {'All SSIDs', enum(SSIDs)}
    # subkeys repeat multiple times. all data=0 except for ROOT-DOMAIN
    # for type=VIRTUALDOMAIN; subkey is All; key is virtualDomain [All Autonomous APs|All SSIDs|All wired|All Wireless]
    # similarly, the keys repeat multiple times, and all data=0 except for ROOT-DOMAIN - [|All Wireless|All SSIDs]
    ('long', 'throughput'),             # total throughput in Kbps
    ('ClientCountTypeEnum', 'type'),    # filter
    ('long', 'wired100MReceived'),      # 0
    ('long', 'wired100MSent'),          # 0
    ('long', 'wired100MThroughput'),    # 0
    ('long', 'wired10GReceived'),       # appeared in 3.6
    ('long', 'wired10GSent'),           # appeared in 3.6
    ('long', 'wired10GThroughput'),     # appeared in 3.6
    ('long', 'wired10MReceived'),       # 0
    ('long', 'wired10MSent'),           # 0
    ('long', 'wired10MThroughput'),     # 0
    ('long', 'wired1GReceived'),        # 0
    ('long', 'wired1GSent'),            # 0
    ('long', 'wired1GThroughput')       # 0
).set_id_field('@id').set_time_field('collectionTime')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )
'''WCSDBA 	DEVICES
select mei.id as id, mne.networkelement_id as deviceId, mei.communicationstate as reachability,
    mei.lifecyclestate as managementStatus, ist.adminstatus as adminStatus, res.name as deviceName,
    ipdns.managedaddress as ipAddress, mne.ProductType_Value as deviceType,
    mei.inventorystatusdetail as collectionDetail,
    coalesce(mei.inventorycollectiontime,mei.LASTINVENTORYATTEMPTENDTIME) as collectionTime,
    mne.softwaretype as softwareType, mne.softwareversion as softwareVersion, mei.createTime as creationTime,
    mne.syslocation as location, mne.prdctfmly_value as productFamily,
    (select count(id) from alarm a where a.nttyAddrss7_address = mne.mngmntaddrss_address and a.severity =1
        and a.alarmDisplayable = 1) as criticalAlarms,
    (select count(id) from alarm a where a.nttyAddrss7_address = mne.mngmntaddrss_address and a.severity =2
        and a.alarmDisplayable = 1) as majorAlarms,
    (select count(id) from alarm a where a.nttyAddrss7_address = mne.mngmntaddrss_address and a.severity =3
        and a.alarmDisplayable = 1) as minorAlarms,
    (select count(id) from alarm a where a.nttyAddrss7_address = mne.mngmntaddrss_address and a.severity =4
        and a.alarmDisplayable = 1) as warningAlarms,
    (select count(id) from alarm a where a.nttyAddrss7_address = mne.mngmntaddrss_address and a.severity =5
        and a.alarmDisplayable = 1) as clearedAlarms,
    (select count(id) from alarm a where a.nttyAddrss7_address = mne.mngmntaddrss_address and a.severity =6
        and a.alarmDisplayable = 1) as informationAlarms,
    mei.authEntityId as authEntityId, mei.authEntityClass as authEntityClass
from managedelementinterface mei left join networkresource res on res.managedelementinterface_id = mei.id
    left join networkelement mne on mne.networkelement_id = res.id
    left join ipaddresstodnsmapping ipdns on ipdns.mapping_id = mei.id
    left join inventorystatus ist on ist.managedelementinterface_id=mei.id
where res.className is null or res.className != 'ManagedComputeElement'
'''
offset += 5*60.0
# One record for each device
add_table(production, Table(
    'v4', 'data', 'Devices', True, DAY + offset, NUMDEV,
    ('long', '@id'),                    # release 3.x changed string-->long
    # DETERMINE WHICH ID CORRELATES TO OTHER IDS FOR THESE DEVICES
    ('String', '@displayName', None),   # duplicates @id
    ('DeviceAdminStatusEnum', 'adminStatus'),  # 2017-02-16 added str; v4-->enum
    # ('smallint', 'clearedAlarms'),    # removed in v3
    ('String', 'collectionDetail'),     # detailed status of inventory collection
    ('InventoryCollectionStatusEnum', 'collectionStatus'),  # last status
    ('Date', 'collectionTime'),         # Instant. Time of collection
    ('Date', 'creationTime'),           # Instant. Time when the device was created
    # ('smallint', 'criticalAlarms'),	# removed in v3
    ('long', 'deviceId'),               # management net element assoc w/ device
    ('String', 'deviceName'),           # name of the device
    ('String', 'deviceType'),           # Type of device
    # ('smallint', 'informationAlarms'),	# removed in v3
    # ('String', 'instanceUuid'),	    # originally doc. removed in v1
    ('String', 'ipAddress'),            # preferred management access IP address
    ('String', 'location'),             # system location
    # ('smallint', 'majorAlarms'),	    # removed in v3
    ('LifecycleStateEnum', 'managementStatus'),
    ('array', 'manufacturerPartNrs'),
    # ('smallint', 'minorAlarms'),	    # removed in v3
    ('String', 'productFamily'),
    ('ReachabilityStateEnum', 'reachability'),
    ('String', 'softwareType'),
    ('String', 'softwareVersion'),
    # ('smallint', 'warningAlarms'),    # removed in v3
)
          # .subTable('manufacturerPartNrs', [('float', 'polledTime'), ('long', '@id')],	# Array added in v3.
          # ('String', 'partNumber')
          # )
          .set_id_field('@id')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )
'''
WCSDBA 	EVENTS 	784
select e.id as id, e.source as source, e.severity as severity, e.notificationtimestamp as timeStamp, e.id as eventId,
e.notificationtimestamp as eventFoundAt, e.category_ordinal as category_ordinal, e.category_value as category_value,
e.eventtype_ordinal as condition_ordinal, e.eventtype_value as condition_value, e.description as description,
e.displayname as deviceName, e.alarmforevents_id as correlated, e.authEntityId as authEntityId,
e.authEntityClass as authEntityClass, e.nttyaddrss7_address as nttyaddrss7_address,
e.devicetimestamp as devicetimestamp, e.srcObjectId as srcObjectId, e.srcObjectClassId as srcObjectClassId
from event e 
'''
# ***** sequence name for WSCDBA's EVENT table, column=ID
# at 2020/09/26T12:15 EDT,value was 1026181421. Maximum is 9999999999999999999999999999
# ALTER SEQUENCE event_seq INCREMENT BY 5000000;
# SELECT event_seq.nextval from DUAL;
# ALTER SEQUENCE event_seq INCREMENT BY 1;
# data is deleted after 2 months
add_table(production, Table(
    'v4', 'data', 'Events', False, 2*DAY + 5*HOUR/2, 2300,
    ('long', '@id', None),              # release 3.x changed string-->long
    ('String', '@displayName', None),   # duplicates eventId uncommented 2018-07-01
    # ('String', '@uuid'),			    # originally doc, but not present in v1
    ('smallint', 'category_ordinal'),   # major cat index. undoc in v3
    ('String', 'category_value'),       # major cat text. v3 silently renamed category -->
    # ('String', 'category'),		    # major cat. enum in doc, but not in output
    ('smallint', 'condition_ordinal'),  # event type index within major cat. undoc in v3
    ('String', 'condition_value'),      # event type within major cat. undoc in v3
    # ('String', 'condition'),		    # event type. enum in doc, but incorrect
    ('long', 'correlated'),             # The alarm ID correlated for this event
    ('String', 'description'),          # free text description of the event/alarm
    ('String', 'deviceName'),           # reporting entity. E.g. AP apName, Interface 802.11b/g/n
    ('Date', 'deviceTimestamp'),  # optional time when event occurred; True for 202101 9800 controller
    ('Date', 'eventFoundAt'),           # time when the event was found
    ('long', 'eventId'),                # release 3.x changed string-->long
    # ('String', 'instanceUuid'),	    # originally doc, but not found in v1
    ('AlarmSeverityEnum', 'severity'),
    ('String', 'source'),               # entity about which the event/alarm is reported
    # typically of the form [LradIf!apMac!slotId|UnifiedAp!apMac]
    ('Date', 'timeStamp'),              # time of event, or if not avail. record creation
).set_id_field('eventId').set_time_field('eventFoundAt')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          .set_rollup(61*DAY)           # Events are apparently kept for 2 months
          )
'''WCSDBA 	GROUPSPECIFICATION
select coalesce(gig.parentid,-1) as parentid, grp.instanceid as id,
trim(leading '/' from grp.groupnamehierarchy||'/'||grp.instancename) groupPath,
grp.instancename groupName, grp.description description
from ( select *
    from xgs_device_group_view union select * from xgs_location_group_view
        union select * from xgs_userdefined_group_view ) grp,
    xgs_groupingroup gig
where grp.instanceid=gig.childid(+)
'''
# For navigating Groups. Defines three trees of groups.
# One each for {User Defined, Device Type, Location}
offset += 5*60.0
add_table(production, Table(
    'v2', 'data', 'GroupSpecification', True, DAY + offset, 800,
    ('long', '@id'),                    # group Id. release 3.x changed string-->long
    ('String', '@displayName', None),   # dupl groupName. uncommented 2018-07-01
    ('String', 'description'),          # Description of the group
    ('String', 'groupName'),            # name of the group
    ('String', 'groupPath'),            # full hierarchy path of the group
    # ('String', 'instanceUuid'),	    # doc but not present in v1. removed in v2
    ('long', 'parentId')                # id of parent or -1 if a root group
).set_id_field('@id')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )

'''WCSDBA 	HISTORICALCLIENTCOUNTS
select cc.id as id, cc.type as type, case when cc.type=3 then sd.domainname else cc.key end as key,
cc.subkey as subkey, cc.eventTime as collectionTime, cc.totalassocount as count, cc.totalauthcount as authcount,
cc.protocolacount as dot11aCount, cc.protocolaauthcount as dot11aAuthCount, cc.protocolbcount as dot11bCount,
cc.protocolbauthcount as dot11bAuthCount, cc.protocolgcount as dot11gCount, cc.protocolgauthcount as dot11gAuthCount,
cc.protocoln24count as dot11n2_4Count, cc.protocoln24authcount as dot11n2_4AuthCount,
cc.protocoln5count as dot11n5Count, cc.protocoln5authcount as dot11n5AuthCount, cc.protocolaccount as dot11acCount,
cc.protocolacauthcount as dot11acAuthCount, cc.protocolax24count as dot11ax2_4Count,
cc.protocolax24authcount as dot11ax2_4AuthCount, cc.protocolax5count as dot11ax5Count,
cc.protocolax5authcount as dot11ax5AuthCount, cc.protocolwcount as wgbCount, cc.protocolwauthcount as wgbAuthCount,
cc.wiredSpeed10mCount as wired10MCount, cc.wiredSpeed10mAuthCount as wired10MAuthCount,
cc.wiredSpeed100mCount as wired100MCount, cc.wiredSpeed100mAuthCount as wired100MAuthCount,
cc.wiredSpeed1gCount as wired1GCount, cc.wiredSpeed1gAuthCount as wired1GAuthCount,
cc.wiredSpeed10gCount as wired10GCount, cc.wiredSpeed10gAuthCount as wired10GAuthCount
from ClientCount cc left outer join BaseServiceDomain sd on cast(sd.id as varchar(255))=cc.key
where type in (0,2,3,4,8,10)
'''
# Posted every 5 minutes. Records deleted after 24 hours.
add_table(production, Table(
    'v4', 'data', 'HistoricalClientCounts', False, 3*HOUR, int(NUMHIST*SAMPERHR),
    ('long', '@id'),                    # release 3.x changed from string-->long
    ('String', '@displayName', None),   # copy of @id uncommented 2018-07-01
    ('smallint', 'authCount'),          # as of last collection time
    ('epochMillis', 'collectionTime'),  # time when record was collected
    ('smallint', 'count'),              # total client count
    ('smallint', 'dot11aAuthCount'),
    ('smallint', 'dot11aCount'),
    ('smallint', 'dot11acAuthCount'),
    ('smallint', 'dot11acCount'),
    ('smallint', 'dot11ax2_4AuthCount'),
    ('smallint', 'dot11ax2_4Count'),
    ('smallint', 'dot11ax5AuthCount'),
    ('smallint', 'dot11ax5Count'),
    ('smallint', 'dot11bAuthCount'),
    ('smallint', 'dot11bCount'),
    ('smallint', 'dot11gAuthCount'),
    ('smallint', 'dot11gCount'),
    ('smallint', 'dot11n2_4AuthCount'),
    ('smallint', 'dot11n2_4Count'),
    ('smallint', 'dot11n5AuthCount'),
    ('smallint', 'dot11n5Count'),
    # ('String', 'instanceUuid'),	    # originally doc, but removed from v1
    ('String', 'key'),
    ('String', 'subkey'),
    # for type=ACCESSPOINT; subkey is {'All', enum(SSIDs)}; key is an apMac
    # for type=DEVICE; subkey is {'All', enum(SSIDs)}; key is controller Ip
    # for type=MAPLOCATION; subkey is {'All', enum(SSIDs)}; key is a GroupSpecification.groupName
    # data is useless because e.g. 'Floor 1' is repeated w/o qualification
    # for type=SSID; subkey is {virtual domain, 'ROOT-DOMAIN'}; key is {'All SSIDs', enum(SSIDs)}
    # subkeys repeat multiple times. all data=0 except for ROOT-DOMAIN
    # for type=VIRTUALDOMAIN; subkey is All; key is virtualDomain [All Autonomous APs|All SSIDs|All wired|All Wireless]
    # similarly, the keys repeat multiple times, and all data=0 except for ROOT-DOMAIN - [|All Wireless|All SSIDs]
    ('ClientCountTypeEnum', 'type'),
    ('smallint', 'wgbAuthCount'),       # authenticated as WGB or wired guest
    ('smallint', 'wgbCount'),           # connected as WorkGroup Bridge or wired guest
    ('smallint', 'wired100MAuthCount'),
    ('smallint', 'wired100MCount'),
    ('smallint', 'wired10GAuthCount'),  # appeared in 3.6
    ('smallint', 'wired10GCount'),      # appeared in 3.6
    ('smallint', 'wired10MAuthCount'),
    ('smallint', 'wired10MCount'),
    ('smallint', 'wired1GAuthCount'),
    ('smallint', 'wired1GCount')
    # ('String', 'adminStatus')	        # undoc. appeared in 2017-02-16, then undoc
).set_id_field('@id').set_time_field('collectionTime')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )

'''WCSDBA 	HISTORICALCLIENTSTATS
select cs.id as id, cs.macAddress as macAddress, cs.eventTime as collectionTime, cs.rssi as rssi, cs.snr as snr,
cs.bytesReceived as bytesReceived, cs.bytesSent as bytesSent, cs.packetsReceived as packetsReceived,
cs.packetsSent as packetsSent, cs.dataRate as dataRate, cs.raPacketsDropped as raPacketsDropped,
cs.clientDataRetries as dataRetries, cs.clientRtsRetries as rtsRetries, cs.txBytesDropped as txBytesDropped,
cs.rxBytesDropped as rxBytesDropped, cs.txPacketsDropped as txPacketsDropped, cs.rxPacketsDropped as rxPacketsDropped
from StationInfo cs
'''
# Cumulative (bytes, packets) x (sent, received, dropped|retries) by client MAC
# Active sessions posted every 15 minutes. Deleted after 24 hours
# statistics are during this session
add_table(production, Table(
    'v4', 'data', 'HistoricalClientStats', False, 6*HOUR, 36000,
    ('long', '@id'),                    # Session id. release 3.x changed string-->long
    ('String', '@displayName', None),   # copy of @id uncommented 2018-07-01
    ('long', 'bytesReceived'),          # cumulative bytes received
    ('long', 'bytesSent'),              # cumulative bytes sent
    ('epochMillis', 'collectionTime'),  # Unix epoch millis
    ('float', 'dataRate'),              # reading data rate Mbps
    ('long', 'dataRetries'),            # cumulative data Retries
    # ('String', 'instanceUuid'),	    # originally doc. removed in v1
    ('String', 'macAddress_octets'),    # client MAC
    ('long', 'packetsReceived'),        # cumulative packets received
    ('long', 'packetsSent'),            # cumulative packets Sent
    ('long', 'raPacketsDropped'),       # cumulative IPv6 RA packets dropped
    ('smallint', 'rssi'),               # RSSI (dBm) as measured by AP
    ('long', 'rtsRetries'),             # cumulative RTS Retries
    ('long', 'rxBytesDropped'),         # cumulative rx Bytes dropped
    ('long', 'rxPacketsDropped'),       # cumulative rx Packets dropped
    ('smallint', 'snr'),                # SNR as measured by the AP
    ('long', 'txBytesDropped'),         # cumulative tx Bytes dropped
    ('long', 'txPacketsDropped')        # cumulative tx Packets dropped
).set_id_field('@id').set_time_field('collectionTime')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )

'''WCSDBA 	HISTORICALCLIENTTRAFFICS
select ct.id as id, ct.type as type, case when ct.type=3 then sd.domainname else ct.key end as key,
ct.subkey as subkey, ct.eventTime as collectionTime,
ct.protocolaSent+ct.protocolbSent+ct.protocolgSent+ct.protocoln24Sent+ct.protocoln5Sent+ct.protocolacSent
    + ct.protocolax24Sent+ct.protocolax5Sent+ct.wiredspeed10mSent+ct.wiredspeed100mSent+ct.wiredspeed1gSent
    +ct.wiredspeed10gSent as sent,
ct.protocolaReceived+ct.protocolbReceived+ct.protocolgReceived+ct.protocoln24Received+ct.protocoln5Received
    +ct.protocolacReceived+ ct.protocolax24Received+ct.protocolax5Received+ct.wiredspeed10mReceived
    +ct.wiredspeed100mReceived+ct.wiredspeed1gReceived+ct.wiredspeed10gReceived as received,
ct.protocolaThroughput+ct.protocolbThroughput+ct.protocolgThroughput+ct.protocoln24Throughput+ct.protocoln5Throughput
    +ct.protocolacThroughput+ ct.protocolax24Throughput+ct.protocolax5Throughput+ct.wiredspeed10mThroughput
    +ct.wiredspeed100mThroughput+ct.wiredspeed1gThroughput+ct.wiredspeed10gThroughput as throughput,
ct.protocolaSent as dot11aSent, ct.protocolaReceived as dot11aReceived, ct.protocolaThroughput as dot11aThroughput,
ct.protocolbSent as dot11bSent, ct.protocolbReceived as dot11bReceived, ct.protocolbThroughput as dot11bThroughput,
ct.protocolgSent as dot11gSent, ct.protocolgReceived as dot11gReceived, ct.protocolgThroughput as dot11gThroughput,
ct.protocoln24Sent as dot11n2_4Sent, ct.protocoln24Received as dot11n2_4Received,
ct.protocoln24Throughput as dot11n2_4Throughput, ct.protocoln5Sent as dot11n5Sent,
ct.protocoln5Received as dot11n5Received, ct.protocoln5Throughput as dot11n5Throughput,
ct.protocolacSent as dot11acSent, ct.protocolacReceived as dot11acReceived,
ct.protocolacThroughput as dot11acThroughput, ct.protocolax24Sent as dot11ax2_4Sent,
ct.protocolax24Received as dot11ax2_4Received, ct.protocolax24Throughput as dot11ax2_4Throughput,
ct.protocolax5Sent as dot11ax5Sent, ct.protocolax5Received as dot11ax5Received,
ct.protocolax5Throughput as dot11ax5Throughput, ct.wiredSpeed10mSent as wired10MSent,
ct.wiredSpeed10mReceived as wired10MReceived, ct.wiredSpeed10mThroughput as wired10MThroughput,
ct.wiredSpeed100mSent as wired100MSent, ct.wiredSpeed100mReceived as wired100MReceived,
ct.wiredSpeed100mThroughput as wired100MThroughput, ct.wiredSpeed1gSent as wired1GSent,
ct.wiredSpeed1gReceived as wired1GReceived, ct.wiredSpeed1gThroughput as wired1GThroughput,
ct.wiredSpeed10gSent as wired10GSent, ct.wiredSpeed10gReceived as wired10GReceived,
ct.wiredSpeed10gThroughput as wired10GThroughput
from ClientTraffic ct left outer join BaseServiceDomain sd on cast(sd.id as varchar(255))=ct.key
where type in (0,2,3,4,8,10)
'''
# Cumulative (Received,Sent,Throughput) x (a,ac,d,g,n2.4,5,...) by element[Key+Type]
# Posted every 15 minutes
add_table(production, Table(
    'v4', 'data', 'HistoricalClientTraffics', False, 3*HOUR, int(NUMHIST*SAMPERHR),
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),   # copy of @id uncommented 2018-07-01
    # ('String', '@uuid'),			    # removed from documentation in v1+
    ('epochMillis', 'collectionTime'),
    ('long', 'dot11aReceived'),         # cumulative bytes received
    ('long', 'dot11aSent'),             # cumulative bytes sent
    ('long', 'dot11aThroughput'),       # cumulative throughput in Kbps
    ('long', 'dot11acReceived'),        # cumulative bytes received
    ('long', 'dot11acSent'),            # cumulative bytes sent
    ('long', 'dot11acThroughput'),      # total throughput in Kbps
    ('long', 'dot11ax2_4Received'),     # cumulative bytes received
    ('long', 'dot11ax2_4Sent'),         # cumulative bytes sent
    ('long', 'dot11ax2_4Throughput'),   # total throughput in Kbps
    ('long', 'dot11ax5Received'),       # cumulative bytes received
    ('long', 'dot11ax5Sent'),           # cumulative bytes sent
    ('long', 'dot11ax5Throughput'),     # total throughput in Kbps
    ('long', 'dot11bReceived'),         # cumulative bytes received
    ('long', 'dot11bSent'),             # cumulative bytes sent
    ('long', 'dot11bThroughput'),       # cumulative throughput in Kbps
    ('long', 'dot11gReceived'),         # cumulative bytes received
    ('long', 'dot11gSent'),             # cumulative bytes sent
    ('long', 'dot11gThroughput'),       # total throughput in Kbps
    ('long', 'dot11n2_4Received'),      # cumulative bytes received
    ('long', 'dot11n2_4Sent'),          # cumulative bytes sent
    ('long', 'dot11n2_4Throughput'),    # total throughput in Kbps
    ('long', 'dot11n5Received'),        # cumulative bytes received
    ('long', 'dot11n5Sent'),            # cumulative bytes sent
    ('long', 'dot11n5Throughput'),      # cumulative throughput in Kbps
    # ('String', 'instanceUuid'),	    # originally doc. removed in v1.x
    ('String', 'key'),                  # byType {MAC, IP address, 'All Guest', text, SSID, text}
    ('long', 'received'),               # total bytes received
    ('long', 'sent'),                   # total bytes sent
    ('String', 'subkey'),               # depends on type:
    # for type=ACCESSPOINT; subkey is {'All', enum(SSIDs)}; key is an apMac
    # for type=DEVICE; subkey is {'All', enum(SSIDs)}; key is controller Ip
    # for type=MAPLOCATION; subkey is {'All', enum(SSIDs)}; key is a GroupSpecification.groupName
    # data is useless because e.g. 'Floor 1' is repeated w/o qualification
    # for type=SSID; subkey is {virtual domain, 'ROOT-DOMAIN'}; key is {'All SSIDs', enum(SSIDs)}
    # subkeys repeat multiple times. all data=0 except for ROOT-DOMAIN
    # for type=VIRTUALDOMAIN; subkey is All; key is virtualDomain [All Autonomous APs|All SSIDs|All wired|All Wireless]
    # similarly, the keys repeat multiple times, and all data=0 except for ROOT-DOMAIN - [|All Wireless|All SSIDs]
    ('long', 'throughput'),             # total throughput in Kbps
    ('ClientCountTypeEnum', 'type'),    # filter
    ('long', 'wired100MReceived'),      # 0
    ('long', 'wired100MSent'),          # 0
    ('long', 'wired100MThroughput'),    # 0
    ('long', 'wired10GReceived'),       # appeared in 3.6
    ('long', 'wired10GSent'),           # appeared in 3.6
    ('long', 'wired10GThroughput'),     # appeared in 3.6
    ('long', 'wired10MReceived'),       # 0
    ('long', 'wired10MSent'),           # 0
    ('long', 'wired10MThroughput'),     # 0
    ('long', 'wired1GReceived'),        # 0
    ('long', 'wired1GSent'),            # 0
    ('long', 'wired1GThroughput')       # 0
).set_id_field('@id').set_time_field('collectionTime')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )

'''WCSDBA 	HISTORICALRFCOUNTERS
select cs.id as id, cs.macAddress as macAddress, cs.slotId as slotId, cs.eventTime as collectionTime,
cast(to_date('01-jan-1970','dd-mon-yyyy') as timestamp) + cs.eventTime/86400000 as CollectionTimeInDateForm,
cs.fcsErrorCount as fcsErrorCount, cs.txfragmentcount as txFragmentCount, cs.rxfragmentcount as rxFragmentCount,
cs.rxmulticastframecount as rxMulticastFrameCount, cs.txmulticastframecount as txMulticastFrameCount,
cs.failedCount as failedCount, cs.retryCount as retryCount, cs.multipleretrycount as multipleRetryCount,
cs.frameduplicatecount as frameDuplicateCount, cs.txframecount as txFrameCount, cs.rtssuccesscount as rtsSuccessCount,
cs.rtsfailurecount as rtsFailureCount, cs.ackfailurecount as ackFailureCount,
cs.wepundecryptablecount as wepUndecryptableCount
from LradIfCounterStats cs
'''
# Posted every 20 minutes. Data deleted after 24 hours
# each count value is cumulative total for all time.
add_table(production, Table(
    'v4', 'data', 'HistoricalRFCounters', False, 5*HOUR, 4*2*NUMAP*3,
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),   # copy of @id uncommented 2018-07-01
    ('long', 'ackFailureCount'),        # cumulative count of ACK failures
    ('Date', 'collectionTime'),      # time that this collection finished. incorrect UTC prior to 20210501
    # doc changed from string-->Date in v4, but data is not a date
    ('long', 'failedCount'),            # cumulative count of Failures
    ('long', 'fcsErrorCount'),          # cumulative count of Errors
    ('long', 'frameDuplicateCount'),
    # ('String', 'instanceUuid'),	    # originally present, but removed in v1x
    ('String', 'macAddress_octets'),    # Base radio MAC
    ('long', 'multipleRetryCount'),     # cumulative count of Multiple Retries
    ('long', 'retryCount'),             # cumulative count of Retries
    ('long', 'rtsFailureCount'),        # cumulative count of RTS Failures
    ('long', 'rtsSuccessCount'),        # cumulative count of RTS Successes
    ('long', 'rxFragmentCount'),        # cumulative count of rx fragments
    ('long', 'rxMulticastFrameCount'),  # cumulative count of rx Multicast frames
    ('smallint', 'slotId'),             # [0:1] changed from string to int in v4
    ('long', 'txFragmentCount'),        # cumulative count of tx Fragments
    ('long', 'txFrameCount'),           # cumulative count of tx Frames
    ('long', 'txMulticastFrameCount'),  # cumulative count of tx Multicast frames
    ('long', 'wepUndecryptableCount')   # cumulative count of non-decryptable WEP
).set_id_field('@id').set_time_field('collectionTime')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )

'''WCSDBA 	HISTORICALRFLOADSTATS
select ls.id as id, ls.macAddress as macAddress, radio.lradethernetmac as ethernetMac,
radio.authentityid as authentityid, ls.slotId as slotId, ls.eventTime as collectionTime,
cast(to_date('01-jan-1970','dd-mon-yyyy') as timestamp) + ls.eventTime/86400000 as CollectionTimeInDateForm,
coalesce(radio.numberOfClients, 0) as clientCount, ls.txUtilization as txUtilization,
ls.rxUtilization as rxUtilization, ls.channelUtilization as channelUtilization,
ls.poorCoverageClients as poorCoverageClients
from LradIfLoadStats ls, BaseRadio radio
where ls.macAddress=radio.macAddress and ls.slotId=radio.slotId
'''
# introduced in v3 w/changes in v4
# Posted every 20 minutes. Data is deleted after 24 hours.
add_table(production, Table(
    'v4', 'data', 'HistoricalRFLoadStats', False, 5*HOUR, 4*2*NUMAP*3,
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),
    ('smallint', 'channelUtilization'),  # percent [0:100]
    ('smallint', 'clientCount'),        # number of associated clients
    ('Date', 'collectionTime'),         # date-time. incorrect UTC prior to 20210501
    # doc string but epochMillis. String-->Date in v4
    ('String', 'ethernetMac_octets'),   # AP's ethernet MAC
    ('String', 'macAddress_octets'),    # base radio MAC
    ('smallint', 'poorCoverageClients'),  # count?
    ('smallint', 'rxUtilization'),      # percent [0:100]
    ('smallint', 'slotId'),             # [0|1]
    ('smallint', 'txUtilization')       # percent [0:100]
).set_id_field('@id').set_time_field('collectionTime')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )

'''WCSDBA 	HISTORICALRFSTATS
select ss.id as id, ss.macAddress as macAddress, radio.lradethernetmac as ethernetMac, ss.slotId as slotId,
ss.eventTime as collectionTime, ss.channelNumber as channelNumber, ss.powerLevel as powerLevel,
ss.operStatus as operStatus, coalesce(radio.numberOfClients, 0) as clientCount, ss.loadProfile as loadProfile,
ss.interferenceProfile as interferenceProfile, ss.noiseProfile as noiseProfile, ss.coverageProfile as coverageProfile,
ls.txUtilization as txUtilization, ls.rxUtilization as rxUtilization, ls.channelUtilization as channelUtilization,
ls.poorCoverageClients as poorCoverageClients from LradIfStats ss, LradIfLoadStats ls, BaseRadio radio
where ss.eventTime=ls.eventTime and ss.macAddress=ls.macAddress and ss.slotId=ls.slotId
    and ss.macAddress=radio.macAddress and ss.slotId=radio.slotId
'''
# Apparently sampled every 20 minutes. However not every sample is present.
# Maybe a sample is not actually posted if it is the same as the previous?
# At 30 days is twice/day; in last day as often as at every 20 minutes.
# On further investigation, samples start disappearing after 20 minutes
add_table(production, Table(
    'v4', 'data', 'HistoricalRFStats', False, 60*MINUTE, 4*2*NUMAP*3,
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),   # copy of @id
    ('ChannelNumberEnum', 'channelNumber'),
    # ('smallint', 'channelUtilization'),  # moved to HistoricalRFLoadStats in v3
    ('smallint', 'clientCount'),
    ('Date', 'collectionTime'),         # date-time. incorrect UTC prior to 20210501
    # doc changed string->Date in v4, but is not date text
    ('RFProfileEnum', 'coverageProfile'),
    ('String', 'ethernetMac_octets'),   # AP MAC
    # ('String', 'instanceUuid'),	    # originally doc. removed in v1
    ('RFProfileEnum', 'interferenceProfile'),
    ('RFProfileEnum', 'loadProfile'),
    ('String', 'macAddress_octets'),    # base radio MAC
    ('RFProfileEnum', 'noiseProfile'),
    ('RadioOperStatusEnum', 'operStatus'),
    # ('smallint', 'poorCoverageClients'), # moved to new HistoricalRFLoadStats in v3
    ('smallint', 'powerLevel'),  # [1:8]
    # ('smallint', 'rxUtilization'),	# moved to the HistoricalRFLoadStats in v3
    ('smallint', 'slotId'),  # Changed string-->int in v4
    # ('smallint', 'txUtilization')		# moved to the HistoricalRFLoadStats in v3
).set_id_field('@id').set_time_field('collectionTime')
          .set_rollup(2*HOUR)
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )
'''
'''
# this table will hopefully be read by the serviceDomain generator
add_table(archive, Table('v4', 'op/maps', 'image', True, DAY + offset, 200,
                         ('long', 'mapId'),
                         ('String', 'file_name')
                         ).set_id_field('mapId')
          )

offset += 5*60.0
'''WCSDBA 	RADIODETAILSV4
select radio.id as id, radio.macAddress as baseRadioMac, radio.lradethernetmac as ethernetMac,
radio.lradifname as apName, radio.authentityId as authEntityId, radio.authentityClass as authEntityClass,
radio.ipaddress_address as apIpAddress, radio.ipaddress_addressType as apIpAddressT,
ne.mngmntaddrss_address as controllerIpAddress, ne.mngmntaddrss_addresstype as controllerIpAddressT,
radio.slotid as slotId,
case when radio.ifType=1 then
        case when dot11n.ifType11nCapable=0 then '802.11b/g'
            when dot11n.ifType11nCapable=1 then '802.11b/g/n' else '802.11b/g' end
    when radio.ifType=2 then
        case when dot11n.ifType11nCapable=0 then '802.11a' when dot11n.ifType11nCapable=1 then case
            when dot11n.dot11acenabled = 0 then '802.11a/n' when dot11n.dot11acenabled = 1 then case
                when dot11n.slotid = 2 then '802.11ac' else '802.11a/n/ac' end end
    else '802.11a' end else 'Unknown' end as radioType,
    radio.adminstatus as adminStatus, radio.operstatus as operstatus, radio.status as alarmStatus,
    coalesce(dot11n.iftype11ncapable,0) as dot11nCapable, radio.switchPort as port,
    radio.channelnumber as channelNumber, radio.powerlevel as powerLevel,
    case when radio.powerlevel = 1 then txPower.powerLevel1
        when radio.powerlevel = 2 then txPower.powerLevel2 when radio.powerlevel = 3 then txPower.powerLevel3
        when radio.powerlevel = 4 then txPower.powerLevel4 when radio.powerlevel = 5 then txPower.powerLevel5
        when radio.powerlevel = 6 then txPower.powerLevel6 when radio.powerlevel = 7 then txPower.powerLevel7
        when radio.powerlevel = 8 then txPower.powerLevel8 else null end as txPowerOutput,
    radio.phytxpowercontrol as txPowerControl, coalesce(radio.numberofclients, 0) as clientCount,
    case when wlc.isEwlc = 1 then null else coalesce(dot11n.ifSiCapable, 0) end as cleanAirCapable,
    case when wlc.isEwlc = 1 then null else coalesce(dot11n.ifSiEnable, 0) end as cleanAirStatus,
    case when wlc.isEwlc = 1 then null else dot11n.ifSensordOperationalStatus end as cleanAirSensorStatus,
    radio.phychannelassignment as channelControl,
    case when dot11n.iftype11ncapable=1 and radio.owningEntityId is not null then case 
            when dot11n.channelBW > 0 then case
                when dot11n.channelBW=1 then '5 MHz' when dot11n.channelBW=2 then '10 MHz'
                when dot11n.channelBW=3 then '20 MHz' when dot11n.channelBW=4 then '40 MHz'
                when dot11n.channelBW=5 then
                    /* 80 MHz bandwidth is supported by NGWC and by Legacy controllers since productVersion 7.5.1.2 */
                    case when (wlc.isDarya = 1 and REGEXP_REPLACE(REGEXP_REPLACE(wlc.productVersion,
                            '(\d+)', '00\1'), '0+(\d{3})', '\1') >= '003.003.000.000')
                        or (wlc.isNgwc = 0 and REGEXP_REPLACE(REGEXP_REPLACE(wlc.productVersion,
                            '(\d+)', '00\1'), '0+(\d{3})', '\1') >= '007.005.001.002') then '80 MHz'
                        else 'Below 40 MHz' end
                when dot11n.channelBW=6 then '160 MHz' else 'NA' end
            else case when dot11n.channelBandWidth=1 then '5 MHz'
                when dot11n.channelBandWidth=2 then '10 MHz'
                when dot11n.channelBandWidth=3 then '20 MHz'
                when dot11n.channelBandWidth=4 then 'Above 40 MHz'
                when dot11n.channelBandWidth=5 then 'Below 40 MHz'
                else 'NA' end end
        else 'NA' end as channelWidth,
    radio.antennapatternname as antennaName, radio.antennatype as antennaType, radio.antennamode as antennaMode,
    radio.antennaangle*180/3.14 as antennaAzimAngle, radio.antennaelevangle*180/3.14 as antennaElevAngle,
    radio.antennagain as antennaGain, radio.antennadiversity as antennaDiversity, radio.radiorole as radioRole,
    case when radio.radioSubType=5 and xorRadioMode=1 and radio.xorRadioBand=1 then '2.4 GHz'
        when radio.radioSubType=5 and xorRadioMode=1 and radio.xorRadioBand=2 then '5 GHz'
        when radio.ifType=1 then '2.4 GHz' when radio.ifType=2 then '5 GHz'
        else 'Unknown' end as radioBand
from BaseRadio radio left outer join LradIfDot11n dot11n
    on (dot11n.macAddress=radio.macAddress and dot11n.slotid=radio.slotid)
    left outer join LradIfPhyTxPower txPower on (txPower.macAddress=radio.macAddress and txPower.slotid=radio.slotid)
    left outer join managednetworkelement mne on radio.owningentityid=mne.owningentityid
    left outer join networkelement ne on mne.managednetworkelement_id = ne.networkelement_id
    left outer join WlanControllerWithType wlc on wlc.owningentityid = radio.owningentityid
where radio.classname='LradIf'
'''
# Radio details that are not in 'Historical' data
# one record per radio
add_table(production, Table(
    'v4', 'data', 'RadioDetails', True, DAY + offset, 2*NUMAP,
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),   # copy of @id uncommented 2018-07-01
    ('RadioAdminStatusEnum', 'adminStatus'),
    ('AlarmSeverityEnum', 'alarmStatus'),
    ('float', 'antennaAzimAngle'),      # horizontal angle in degrees
    ('AntennaDiversityEnum', 'antennaDiversity'),  # antenna diversity?
    ('float', 'antennaElevAngle'),      # elevation angle in degrees
    ('smallint', 'antennaGain'),        # external in 2*dBm. e.g. 7 --> 3.5dBm
    ('AntennaModeEnum', 'antennaMode'),
    ('String', 'antennaName'),          # antenna part-no
    ('AntennaTypeEnum', 'antennaType'),
    ('String', 'apIpAddress_address'),  # of the access point; blank if {DOWN}
    ('String', 'apName'),               # name of the AP
    ('String', 'baseRadioMac_octets'),  # MAC of the base radio
    ('ChannelAssignmentEnum', 'channelControl'),
    ('ChannelNumberEnum', 'channelNumber'),
    ('ChannelBandwidthEnum', 'channelWidth'),
    ('boolean', 'cleanAirCapable'),
    ('CleanAirSensorStatus', 'cleanAirSensorStatus'),
    ('boolean', 'cleanAirStatus'),
    ('smallint', 'clientCount'),        # clients connected to the radio interface
    ('String', 'controllerIpAddress_address'),  # for CAPWAP AP only
    ('boolean', 'dot11nCapable'),       # true/false
    ('String', 'ethernetMac_octets'),   # MAC of the ethernet address on the AP
    # ('String', 'instanceUuid'),	    # originally doc, but removed in v1
    ('RadioOperStatusEnum', 'operStatus'),
    ('smallint', 'port'),               # controller port number
    ('smallint', 'powerLevel'),         # power level of the radio [0:8]
    ('RadioBandEnum', 'radioBand'),     # appeared in 3.6
    ('RadioRoleEnum', 'radioRole'),
    ('UnifiedRadioTypeEnum', 'radioType'),
    ('smallint', 'slotId'),             # [0:1]
    ('TxPowerControlEnum', 'txPowerControl'),
    ('smallint', 'txPowerOutput')       # dBm. appeared in 2017-02-16 upgrade
).set_id_field('@id')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )
'''WCSDBA 	RFCOUNTERS
select cs.id as id, cs.macAddress as macAddress, cs.slotId as slotId, cs.eventTime as collectionTime,
cast(to_date('01-jan-1970','dd-mon-yyyy') as timestamp) + cs.eventTime/86400000 as CollectionTimeInDateForm,
cs.fcsErrorCount as fcsErrorCount, cs.txfragmentcount as txFragmentCount, cs.rxfragmentcount as rxFragmentCount,
cs.rxmulticastframecount as rxMulticastFrameCount, cs.txmulticastframecount as txMulticastFrameCount,
cs.failedCount as failedCount, cs.retryCount as retryCount, cs.multipleretrycount as multipleRetryCount,
cs.frameduplicatecount as frameDuplicateCount, cs.txframecount as txFrameCount, cs.rtssuccesscount as rtsSuccessCount,
cs.rtsfailurecount as rtsFailureCount, cs.ackfailurecount as ackFailureCount,
cs.wepundecryptablecount as wepUndecryptableCount
from LradIfCounterStats cs left join LradIfCounterStats cs2
    on cs2.macAddress = cs.macAddress and cs2.slotId = cs.slotId and cs2.eventTime > cs.eventTime
where cs2.eventTime is null
'''
# each count value is cumulative total for all time.
add_table(archive, Table(
    'v4', 'data', 'RFCounters', True, 5*MINUTE, 4*2*NUMAP*3,
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),   # copy of @id uncommented 2018-07-01
    ('long', 'ackFailureCount'),        # cumulative count of ACK failures
    ('Date', 'collectionTime'),         # time that this collection finished. incorrect UTC prior to 20210501
    # doc changed from string-->Date in v4, but data is not a date
    ('long', 'failedCount'),            # cumulative count of Failures
    ('long', 'fcsErrorCount'),          # cumulative count of Errors
    ('long', 'frameDuplicateCount'),
    # ('String', 'instanceUuid'),	    # originally present, but removed in v1x
    ('String', 'macAddress_octets'),    # Base radio MAC
    ('long', 'multipleRetryCount'),     # cumulative count of Multiple Retries
    ('long', 'retryCount'),             # cumulative count of Retries
    ('long', 'rtsFailureCount'),        # cumulative count of RTS Failures
    ('long', 'rtsSuccessCount'),        # cumulative count of RTS Successes
    ('long', 'rxFragmentCount'),        # cumulative count of rx fragments
    ('long', 'rxMulticastFrameCount'),  # cumulative count of rx Multicast frames
    ('smallint', 'slotId'),             # [0:1] changed from string to int in v4
    ('long', 'txFragmentCount'),        # cumulative count of tx Fragments
    ('long', 'txFrameCount'),           # cumulative count of tx Frames
    ('long', 'txMulticastFrameCount'),  # cumulative count of tx Multicast frames
    ('long', 'wepUndecryptableCount')   # cumulative count of non-decryptable WEP
).set_id_field('@id').set_time_field('collectionTime')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )
'''WCSDBA 	RFLOADSTATS
select ls.id as id, ls.macAddress as macAddress, radio.lradethernetmac as ethernetMac,
radio.authentityid as authentityid, ls.slotId as slotId, ls.eventTime as collectionTime,
cast(to_date('01-jan-1970','dd-mon-yyyy') as timestamp) + ls.eventTime/86400000 as CollectionTimeInDateForm,
coalesce(radio.numberOfClients,0) as clientCount, ls.txUtilization as txUtilization, ls.rxUtilization as rxUtilization,
ls.channelUtilization as channelUtilization, ls.poorCoverageClients as poorCoverageClients
from BaseRadio radio, (
    select LradIfLoadStats.*, row_number() over (partition by macAddress, slotId order by eventTime desc) as rank
    from LradIfLoadStats
    where eventTime >= (select max(eventTime) - 1 * 60 * 60 * 1000 from LradIfLoadStats) ) ls
where ls.rank = 1 and ls.macAddress=radio.macAddress and ls.slotId=radio.slotId
'''
# Posted every 20 minutes. Data is deleted after 24 hours.
add_table(archive, Table(
    'v4', 'data', 'RFLoadStats', True, 5*MINUTE, 4*2*NUMAP*3,
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),
    ('smallint', 'channelUtilization'),  # percent [0:100]
    ('smallint', 'clientCount'),        # number of associated clients
    ('Date', 'collectionTime'),         # Date. incorrect UTC prior to 20210501
    # doc string but epochMillis. String-->Date in v4
    ('String', 'ethernetMac_octets'),   # AP's ethernet MAC
    ('String', 'macAddress_octets'),    # base radio MAC
    ('smallint', 'poorCoverageClients'),  # count?
    ('smallint', 'rxUtilization'),      # percent [0:100]
    ('smallint', 'slotId'),             # [0|1]
    ('smallint', 'txUtilization')       # percent [0:100]
).set_id_field('@id').set_time_field('collectionTime')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )
'''WCSDBA 	RFSTATS
select ss.id as id, ss.macAddress as macAddress, radio.lradethernetmac as ethernetMac,
ss.slotId as slotId, ss.eventTime as collectionTime, ss.channelNumber as channelNumber,
ss.powerLevel as powerLevel,
case when ss.powerlevel = 1 then pwr.powerLevel1
    when ss.powerlevel = 2 then pwr.powerLevel2
    when ss.powerlevel = 3 then pwr.powerLevel3
    when ss.powerlevel = 4 then pwr.powerLevel4
    when ss.powerlevel = 5 then pwr.powerLevel5
    when ss.powerlevel = 6 then pwr.powerLevel6
    when ss.powerlevel = 7 then pwr.powerLevel7
    when ss.powerlevel = 8 then pwr.powerLevel8
    else null end as txPowerOutput,
ss.operStatus as operStatus, coalesce(radio.numberOfClients,0) as clientCount, ss.loadProfile as loadProfile,
ss.interferenceProfile as interferenceProfile, ss.noiseProfile as noiseProfile, ss.coverageProfile as coverageProfile,
ls.txUtilization as txUtilization, ls.rxUtilization as rxUtilization, ls.channelUtilization as channelUtilization,
ls.poorCoverageClients as poorCoverageClients
from LradIfStats ss, LradIfLoadStats ls,
    BaseRadio radio left join LradIfPhyTxPower pwr on pwr.macAddress=radio.macAddress and pwr.slotid=radio.slotid
where ss.eventTime=ls.eventTime and ss.macAddress=ls.macAddress and ss.slotId=ls.slotId
    and ss.macAddress=radio.macAddress and ss.slotId=radio.slotId
    and ls.eventTime=(select max(eventTime) from LradIfStats) and ss.eventTime=(select max(eventTime) from LradIfStats)
'''
# Apparently sampled every 20 minutes. However not every sample is present.
# Maybe a sample is not actually posted if it is the same as the previous?
# At 30 days is twice/day; in last day as often as at every 20 minutes.
# On further investigation, samples start disappearing after 20 minutes
add_table(archive, Table(
    'v4', 'data', 'RFStats', False, 5*MINUTE, 4*2*NUMAP*3,
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),   # copy of @id
    ('ChannelNumberEnum', 'channelNumber'),
    # ('smallint', 'channelUtilization'),  # moved to HistoricalRFLoadStats in v3
    ('smallint', 'clientCount'),
    ('Date', 'collectionTime'),         # time. incorrect UTC prior to 20210501
    # doc changed string->Date in v4, but is not date text
    ('RFProfileEnum', 'coverageProfile'),
    ('String', 'ethernetMac_octets'),   # AP MAC
    # ('String', 'instanceUuid'),	    # originally doc. removed in v1
    ('RFProfileEnum', 'interferenceProfile'),
    ('RFProfileEnum', 'loadProfile'),
    ('String', 'macAddress_octets'),    # base radio MAC
    ('RFProfileEnum', 'noiseProfile'),
    ('RadioOperStatusEnum', 'operStatus'),
    # ('smallint', 'poorCoverageClients'), # moved to new HistoricalRFLoadStats in v3
    ('smallint', 'powerLevel'),         # [1:8]
    # ('smallint', 'rxUtilization'),	# moved to the HistoricalRFLoadStats in v3
    ('smallint', 'slotId'),             # Changed string-->int in v4
    # ('smallint', 'txUtilization')		# moved to the HistoricalRFLoadStats in v3
    ('smallint', 'txPowerOutput'),      # not available in HistoricalRFStats
).set_id_field('@id').set_time_field('collectionTime')
          .set_rollup(2*HOUR)
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )

'''
'''
offset += 5*60.0
# The neighborGenerator reads AccessPointDetails into workQ for
# cpi.maxConcurrent worker threads. Worker polls one AP at a time,
# which may take up to 30 seconds. Average is about 1 AP/second per worker.
add_table(archive, Table(
    'v4', 'op/apService', 'rxNeighbors', True, 7*DAY + offset, 10,
    ('long', 'apId'),                   # a request attribute. Not in the response
    ('String', 'macAddress_octets'),    # MAC of the AP's radio
    ('long', 'neighborApId'),           # Id of the neighbor's parent AP
    ('String', 'neighborApName'),       # Name of the neighbor's parent AP
    ('smallint', 'neighborChannel'),    # Channel which the neighbor AP is using
    ('RxNeighborChannelWidthEnum', 'neighborChannelBandwidth'),
    ('String', 'neighborIpAddress_address'),
    ('String', 'neighborMapLocation'),  # name of the service domain location
    ('smallint', 'neighborRSSI'),       # RSSI value of the neighbor
    ('smallint', 'neighborSlotId'),
    ('RadioBandEnum', 'radioBand'),
    ('smallint', 'slotId')              # slotId of AP's radio interface
).set_paged(False).set_generator(neighborGenerator)
          .set_index_table_path('v4/data/AccessPointDetails')
          )
'''WCSDBA 	SITES
select grp.instanceId as id, grp.instanceId as groupId, grp.instanceName as groupName, grp.groupPath as name,
case when bsd.domaintype=1 then 'Campus'
    when bsd.domaintype=2 then 'Building'
    when bsd.domaintype=4 then 'Floor Area'
    when bsd.domaintype=5 then 'Outdoor Area'
    else cast(bsd.domaintype as VARCHAR(20)) end as siteType,
(case when grp.isRootGroup = 1 then (select count(distinct al.alarmId)
        from GroupAlarmsView al join xgs_group grp on grp.instanceid = al.groupId
        where grp.groupNameHierarchy = 'Location' and al.severity = 1)
    else (select count(distinct al.alarmId)
        from GroupAlarmsView al where al.severity = 1 and al.groupId = grp.instanceid) end) as criticalAlarms,
(case when grp.isRootGroup = 1 then (select count(distinct al.alarmId)
        from GroupAlarmsView al join xgs_group grp on grp.instanceid = al.groupId
        where grp.groupNameHierarchy = 'Location' and al.severity = 2)
    else (select count(distinct al.alarmId)
        from GroupAlarmsView al where al.severity = 2 and al.groupId = grp.instanceid) end) as majorAlarms,
(case when grp.isRootGroup = 1 then (select count(distinct al.alarmId)
        from GroupAlarmsView al join xgs_group grp on grp.instanceid = al.groupId
        where grp.groupNameHierarchy = 'Location' and al.severity = 3)
    else (select count(distinct al.alarmId)
        from GroupAlarmsView al where al.severity = 3 and al.groupId = grp.instanceid) end) as minorAlarms,
(case when grp.isRootGroup = 1 then (select count(distinct al.alarmId)
        from GroupAlarmsView al join xgs_group grp on grp.instanceid = al.groupId
        where grp.groupNameHierarchy = 'Location' and al.severity = 4)
    else (select count(distinct al.alarmId)
        from GroupAlarmsView al where al.severity = 4 and al.groupId = grp.instanceid) end) as warningAlarms,
(case when grp.isRootGroup = 1 then (select count(distinct al.alarmId)
        from GroupAlarmsView al join xgs_group grp on grp.instanceid = al.groupId
        where grp.groupNameHierarchy = 'Location' and al.severity = 5)
    else (select count(distinct al.alarmId) from GroupAlarmsView al
        where al.severity = 5 and al.groupId = grp.instanceid) end) as clearedAlarms,
(case when grp.isRootGroup = 1 then (select count(distinct al.alarmId)
        from GroupAlarmsView al join xgs_group grp on grp.instanceid = al.groupId
        where grp.groupNameHierarchy = 'Location' and al.severity = 6)
    else (select count(distinct al.alarmId) from GroupAlarmsView al
        where al.severity = 6 and al.groupId = grp.instanceid) end) as informationAlarms,
(case when grp.isRootGroup = 1 then ((select count(distinct memberid)
        from xgs_groupmembers grp_mem left join xgs_group grp on grp_mem.groupid=grp.instanceId
        where grp.groupNameHierarchy = 'Location') )
    else (select count(distinct mneID) from GroupMembers gm
        where gm.groupid=grp.instanceId AND wapId is NULL)end) as deviceCount,
(case when grp.instanceName = 'Location' and grp.groupNameHierarchy is null then (
        select count (*) from wirelessAccesspoint wap
            left join xgs_groupmembers grp_mem on wap.rawmanagingmne_id = grp_mem.memberid
            left join xgs_group grp2 on grp_mem.groupid=grp2.instanceId
            where grp2.groupNameHierarchy = 'Location')
    else (select count (*) from SiteAccesspoints ap
        where ap.groupid = grp.instanceid) end) as apCount,
(case when grp.isRootGroup = 1 then (select count(*) from baseStation bs
        left join wirelessAccessPoint wap on bs.lradname=wap.lradname
        left join xgs_groupmembers grp_mem on wap.rawmanagingmne_id = grp_mem.memberid
        left join xgs_group grp2 on grp_mem.groupid=grp2.instanceId
        where grp2.groupNameHierarchy = 'Location')
    else (select count(*) from baseStation bs, wirelessAccessPoint wap, networkResource nr, xgs_groupmembers grp_mem
    where bs.lradId=wap.wirelessaccesspoint_id and nr.id = wap.wirelessaccesspoint_id
            and nr.classname = 'UnifiedAp' and grp_mem.memberid = nr.lradmneid
            and grp_mem.groupid=grp.instanceId)end) as clientCount, bsd.locationAddress as locationAddress,
bsd.latitude as latitude, bsd.longitude as longitude, bsd.authEntityClass as authEntityClass,
bsd.authEntityId as authEntityId from xgs_location_group_view grp left outer join baseServiceDomain bsd
    on bsd.name = cast(grp.instanceId as varchar(255))
'''
offset += 5*60.0
# For navigating locations.
# One record for each Campus, Outdoor Area, Building, Floor, Default
# A few floors have longitude, latitude, LocationAddress values
# 'groupId' is a primary key, but retrieval is ordered by group hierarchy, groupId
add_table(production, Table(
    'v4', 'op/groups', 'sites', True, DAY + offset, 10000,
    ('long', '@id', None),              # release 3.x changed string-->long
    # ('smallint', 'apCount'),		    # not present because noMembersCount=true
    # ('smallint', 'clearedAlarms'),    # not present because noAlarms=true
    # ('smallint', 'clientCount'),	    # not present because noMembersCount=true
    # ('smallint', 'criticalAlarms'),   # not present because noAlarms=true
    ('String', 'description'),          # value with new site maps
    # ('smallint', 'deviceCount'), 	    # not present because noMembersCount=true
    ('long', 'groupId'),                # release 3.x changed string-->long
    ('String', 'groupName'),
    # ('smallint', 'informationAlarms'),	# not present because noAlarms=true
    ('boolean', 'isExplicit'),          # CPI never returns a value
    ('float', 'latitude'),              # value w/ new maps, when building, outdoor, campus
    ('String', 'locationAddress'),      # value w/ new maps, when building, outdoor, campus
    ('LocationGroupTypeEnum', 'locationGroupType'),  # value with new site maps
    ('float', 'longitude'),             # value w/ new maps, when building,outdoor area, campus
    # ('smallint', 'majorAlarms'),	    # not present because noAlarms=true
    # ('smallint', 'membersCount'),     # not present because noMembersCount=true
    # ('smallint', 'minorAlarms'),	    # not present because noAlarms=true
    ('String', 'name'),                 # full hierarchy
    ('String', 'siteType'),             # {Campus, Outdoor Area, Building, Floor Area
    # ('smallint', 'unacknowledgedClearedAlarms'),# not present because noAlarms=true
    # ('smallint', 'unacknowledgedCriticalAlarms'),# not present because noAlarms=true
    # ('smallint', 'unacknowledgedInformationAlarms'),# not present because noAlarms=true
    # ('smallint', 'unacknowledgedMajorAlarms'),# not present because noAlarms=true
    # ('smallint', 'unacknowledgedMinorAlarms'),# not present because noAlarms=true
    # ('smallint', 'unacknowledgedWarningAlarms'),# not present because noAlarms=true
    # ('smallint', 'warningAlarms')		# not present because noAlarms=true
).set_id_field('groupId').set_paged(False)
          .set_query_options({'noAlarms': 'true', 'noMembersCount': 'true'})
          )
'''WCSDBA 	SERVICEDOMAINS
SELECT bsd.id as id, bsd.domainName as name, bsd.domainContact as contact, bsd.domainType as domainType,
bsd.parentId as parentId, bsd.name as groupId, bsd.locationAddress as civicLocation, bsd.longitude as longitude,
bsd.latitude as latitude, bsd.width as width, bsd.lengthValue as length, bsd.status as status,
(CASE WHEN bsd.domainType IN (4,5) THEN bsd.height ELSE NULL END) as height,
(CASE WHEN bsd.domainType = 2 THEN bsd.numOfFloors ELSE NULL END) as numOfFloors,
(CASE WHEN bsd.domainType = 2 THEN bsd.numOfBasements ELSE NULL END) as numOfBasements,
bsd.apCount as apCount,
(bsd.dot11aClientCount + bsd.dot11bClientCount + bsd.dot11gClientCount) as wirelessClientsCount,
bsd.oosRadioCount as criticalRadioCount, bsd.dot11aRadioCount as dot11aRadioCount,
bsd.dot11bRadioCount as dot11bRadioCount, bsd.dot11gRadioCount as dot11gRadioCount,
(CASE WHEN bsd.domainType = 4 THEN bsd.floorIndex ELSE NULL END) as floorIndex,
(CASE WHEN bsd.domainType = 4 THEN bsd.xcoordinate ELSE NULL END) as horizontalPosition,
(CASE WHEN bsd.domainType = 4 THEN bsd.ycoordinate ELSE NULL END) as verticalPosition,
cm.modelName as rfModel_name, bsd.authEntityId as authEntityId,
bsd.authEntityClass as authEntityClass FROM BaseServiceDomain bsd LEFT JOIN CalibrationModel cm ON bsd.rfModelId = cm.id
WHERE bsd.classname = 'ServiceDomain'
'''
offset += 5*60.0
add_table(production, Table(
    'v4', 'data', 'ServiceDomains', True, DAY + offset, 200,
    ('long', '@id'),
    ('String', '@displayName'),
    ('smallint', 'apCount'),            # Count of access points
    ('String', 'civicLocation'),        # Location Address
    ('String', 'contact'),              # email address
    ('smallint', 'criticalRadioCount'),  # Count of critical radio interfaces
    ('ServiceDomainTypeEnum', 'domainType'),  # Here MULTI_FLOOR is Building
    ('smallint', 'dot11aRadioCount'),   # Count of 802.11a radio interfaces
    ('smallint', 'dot11bRadioCount'),   # Count of 802.11b radio interfaces
    ('smallint', 'dot11gRadioCount'),   # Count of 802.11g radio interfaces
    # ('String', 'file_name'),		    # name of jpeg image file. Added by generator
    ('smallint', 'floorIndex'),         # only for floor
    ('long', 'groupId'),                # ID of the location group
    ('float', 'height'),                # Height of the floor in feet
    ('float', 'horizontalPosition'),    # feet from left of building to left of floor
    ('double', 'latitude'),             # Longitude of service domain
    ('float', 'length'),                # length of service domain in feet
    ('double', 'longitude'),            # Longitude of service domain
    ('String', 'name'),                 # Name of service domain
    ('smallint', 'numOfBasements'),     # number of basements
    ('smallint', 'numOfFloors'),        # number of floors (for building)
    ('long', 'parentId'),               # groupId of parent Service Domain
    ('String', 'rfModel_name'),         # Calibration model name
    ('AlarmSeverityEnum', 'status'),    # max severity of all alarms in domain
    ('float', 'verticalPosition'),      # feet from top of building to top of floor
    ('float', 'width'),                 # width of the service domain in feet
    ('smallint', 'wirelessClientsCount')  # Count of wireless clients
).set_id_field('@id')
          .set_query_options({'.full': 'true', '.nocount': 'true'})
          )
'''WCSDBA 	NBI_WLANPROFILES
SELECT bwc.id as id, bwc.parentid as parentid, ipdns.managedaddress as managedaddress, bwc.wlanid as wlanid,
bwc.ssid as ssid, bwc.sessiontimeout as sessiontimeout, bwc.blacklisttimeout as blacklisttimeout,
bwc.blacklistingcapability as blacklistingcapability, bwc.adminstatus as adminstatus, bwc.dhcprequired as dhcprequired,
bwc.dhcpserver as dhcpserver, bwc.dhcpservert as dhcpservert,
bwc.WlanWebAuthOnMacFilterFailure as WlanWebAuthOnMacFilterFailure, bwc.wepsecurity as wepsecurity,
bwc.wepauthtype as wepauthtype, bwc.wepencrtype as wepencrtype, bwc.wepdefaultkey as wepdefaultkey,
bwc.wepkeyindex as wepkeyindex, bwc.wepkeyformat as wepkeyformat, bwc.X8021Security as X8021Security,
bwc.X8021EncrType as X8021EncrType, bwc.VpnSecurity as VpnSecurity, bwc.VpnEncrType as VpnEncrType,
bwc.qotdServerAddr as qotdServerAddr, bwc.qotdServerAddrT as qotdServerAddrT,
bwc.vpnPassthroughSecurity as vpnPassthroughSecurity, bwc.vpnPassthroughIpAddress as vpnPassthroughIpAddress,
bwc.vpnPassthroughIpAddressT as vpnPassthroughIpAddressT, bwc.webSecurity as webSecurity,
bwc.radioPolicy as radioPolicy, bwc.webPassthru as webPassthru, bwc.craniteSecurity as craniteSecurity,
bwc.interfaceName as interfaceName, bwc.aclName as aclName, bwc.aaaOverride as aaaOverride,
bwc.wepAllowSharedKeyAuth as wepAllowSharedKeyAuth, bwc.fortressSecurity as fortressSecurity,
bwc.broadcastSsid as broadcastSsid, bwc.wme as wme, bwc.phoneSupport7920 as phoneSupport7920,
bwc.wpa1Wpa2Support as wpa1Wpa2Support, bwc.wpa1Security as wpa1Security, bwc.wpa1EncType as wpa1EncType,
case when bitand(to_number(bwc.wpa1EncType, 'xx'), 128) > 0 then 1 else 0 end as wpa1EncType0,
case when bitand(to_number(bwc.wpa1EncType, 'xx'), 64) > 0 then 1 else 0 end as wpa1EncType1,
case when bitand(to_number(bwc.wpa1EncType, 'xx'), 32) > 0 then 1 else 0 end as wpa1EncType2,
case when bitand(to_number(bwc.wpa1EncType, 'xx'), 16) > 0 then 1 else 0 end as wpa1EncType3,
case when bitand(to_number(bwc.wpa1EncType, 'xx'), 8) > 0 then 1 else 0 end as wpa1EncType4,
case when bitand(to_number(bwc.wpa1EncType, 'xx'), 4) > 0 then 1 else 0 end as wpa1EncType5,
case when bitand(to_number(bwc.wpa1EncType, 'xx'), 2) > 0 then 1 else 0 end as wpa1EncType6,
case when bitand(to_number(bwc.wpa1EncType, 'xx'), 1) > 0 then 1 else 0 end as wpa1EncType7,
bwc.wpa2Security as wpa2Security, bwc.wpa2EncType as wpa2EncType,
case when bitand(to_number(bwc.wpa2EncType, 'xx'), 128) > 0 then 1 else 0 end as wpa2EncType0,
case when bitand(to_number(bwc.wpa2EncType, 'xx'), 64) > 0 then 1 else 0 end as wpa2EncType1,
case when bitand(to_number(bwc.wpa2EncType, 'xx'), 32) > 0 then 1 else 0 end as wpa2EncType2,
case when bitand(to_number(bwc.wpa2EncType, 'xx'), 16) > 0 then 1 else 0 end as wpa2EncType3,
case when bitand(to_number(bwc.wpa2EncType, 'xx'), 8) > 0 then 1 else 0 end as wpa2EncType4,
case when bitand(to_number(bwc.wpa2EncType, 'xx'), 4) > 0 then 1 else 0 end as wpa2EncType5,
case when bitand(to_number(bwc.wpa2EncType, 'xx'), 2) > 0 then 1 else 0 end as wpa2EncType6,
case when bitand(to_number(bwc.wpa2EncType, 'xx'), 1) > 0 then 1 else 0 end as wpa2EncType7,
bwc.authKeyMgmtMode as authKeyMgmtMode,
case when bitand(to_number(bwc.authKeyMgmtMode, 'xx'), 128) > 0 then 1 else 0 end as authKeyMgmtMode0,
case when bitand(to_number(bwc.authKeyMgmtMode, 'xx'), 64) > 0 then 1 else 0 end as authKeyMgmtMode1,
case when bitand(to_number(bwc.authKeyMgmtMode, 'xx'), 32) > 0 then 1 else 0 end as authKeyMgmtMode2,
case when bitand(to_number(bwc.authKeyMgmtMode, 'xx'), 16) > 0 then 1 else 0 end as authKeyMgmtMode3,
case when bitand(to_number(bwc.authKeyMgmtMode, 'xx'), 8) > 0 then 1 else 0 end as authKeyMgmtMode4,
case when bitand(to_number(bwc.authKeyMgmtMode, 'xx'), 4) > 0 then 1 else 0 end as authKeyMgmtMode5,
case when bitand(to_number(bwc.authKeyMgmtMode, 'xx'), 2) > 0 then 1 else 0 end as authKeyMgmtMode6,
case when bitand(to_number(bwc.authKeyMgmtMode, 'xx'), 1) > 0 then 1 else 0 end as authKeyMgmtMode7,
bwc.pskFmt as pskFmt, bwc.presharedKeyHex as presharedKeyHex, bwc.aironetIeSupport as aironetIeSupport,
bwc.mfpSigGenerator as mfpSigGenerator, bwc.mfpClientProtection as mfpClientProtection,
bwc.mfpVersionReq as mfpVersionReq, bwc.wlanClientAclName as wlanClientAclName, bwc.profileName as profileName,
bwc.webRedirect as webRedirect, bwc.peer2peerBlocking as peer2peerBlocking, bwc.isWiredLan as isWiredLan,
bwc.lanType as lanType, bwc.ingressInterface as ingressInterface, bwc.diagnosticsEnable as diagnosticsEnable,
bwc.dateInLong as dateInLong, bwc.nacSupport as nacSupport, bwc.dot11anDtim as dot11anDtim,
bwc.dot11bgnDtim as dot11bgnDtim, bwc.voipSnoopingEnabled as voipSnoopingEnabled,
bwc.coverageHoleDetectionEnable as coverageHoleDetectionEnable, bwc.wlanLoadBalancingEnable as wlanLoadBalancingEnable,
bwc.wlanBandSelectEnable as wlanBandSelectEnable, bwc.passiveClientEnable as passiveClientEnable,
bwc.reapLocalAuth as reapLocalAuth, bwc.reapLocalSwitching as reapLocalSwitching,
bwc.reapLearnClientAddress as reapLearnClientAddress, bwc.scanDeferPriority as scanDeferPriority,
case when bitand(to_number(bwc.scanDeferPriority, 'xx'), 128) > 0 then 1 else 0 end as scanDeferPriority0,
case when bitand(to_number(bwc.scanDeferPriority, 'xx'), 64) > 0 then 1 else 0 end as scanDeferPriority1,
case when bitand(to_number(bwc.scanDeferPriority, 'xx'), 32) > 0 then 1 else 0 end as scanDeferPriority2,
case when bitand(to_number(bwc.scanDeferPriority, 'xx'), 16) > 0 then 1 else 0 end as scanDeferPriority3,
case when bitand(to_number(bwc.scanDeferPriority, 'xx'), 8) > 0 then 1 else 0 end as scanDeferPriority4,
case when bitand(to_number(bwc.scanDeferPriority, 'xx'), 4) > 0 then 1 else 0 end as scanDeferPriority5,
case when bitand(to_number(bwc.scanDeferPriority, 'xx'), 2) > 0 then 1 else 0 end as scanDeferPriority6,
case when bitand(to_number(bwc.scanDeferPriority, 'xx'), 1) > 0 then 1 else 0 end as scanDeferPriority7,
bwc.scanDeferTime as scanDeferTime, bwc.wlanInterfaceMappingType as wlanInterfaceMappingType,
bwc.wlanMulticastInterfaceEnable as wlanMulticastInterfaceEnable, bwc.wlanMulticastInterface as wlanMulticastInterface,
bwc.wlanMulticastDirectEnable as wlanMulticastDirectEnable, bwc.radiusNacState as radiusNacState,
bwc.maxClients as maxClients, bwc.radiusAccMethodListName as radiusAccMethodListName,
bwc.radiusAuthMethodListName as radiusAuthMethodListName, bwc.macFilterMethodListName as macFilterMethodListName,
bwc.webAuthMethodListName as webAuthMethodListName, bwc.webAuthParamMapName as webAuthParamMapName,
bwc.qosUpStreamProfileName as qosUpStreamProfileName, bwc.qosDownStreamProfileName as qosDownStreamProfileName,
bwc.dhcpOpt82Format as dhcpOpt82Format, bwc.dhcpOpt82Ascii as dhcpOpt82Ascii, bwc.dhcpOpt82Rid as dhcpOpt82Rid,
bwc.dhcpOpt82Enable as dhcpOpt82Enable, bwc.qos as qos, bwc.macFiltering as macFiltering,
bwc.wpaSecurity as wpaSecurity, bwc.wpaEncrType as wpaEncrType, bwc.vpnAuthType as vpnAuthType,
bwc.vpnIkeAuthMode as vpnIkeAuthMode, bwc.vpnIkePresharedKey as vpnIkePresharedKey,
bwc.vpnIkePresharedKeySize as vpnIkePresharedKeySize, bwc.vpnIkePhase1Mode as vpnIkePhase1Mode,
bwc.vpnIkeLifetime as vpnIkeLifetime, bwc.vpnIkeDhGroup as vpnIkeDhGroup, bwc.vpnContivity as vpnContivity,
bwc.aclIpv6Name as aclIpv6Name, bwc.webAuthAclName as webAuthAclName, bwc.wpaAuthKeyMgmtMode as wpaAuthKeyMgmtMode,
bwc.wpaAuthPresharedKey as wpaAuthPresharedKey, bwc.wpaAuthPresharedKeyHex as wpaAuthPresharedKeyHex,
bwc.l2tpSecurity as l2tpSecurity, bwc.externalPolicyValidation as externalPolicyValidation,
bwc.rsnSecurity as rsnSecurity, bwc.rsnWpaCompatibility as rsnWpaCompatibility,
bwc.rsnAllowTkipClients as rsnAllowTkipClients, bwc.rsnAuthKeyMgmtMode as rsnAuthKeyMgmtMode,
bwc.rsnAuthPresharedKey as rsnAuthPresharedKey, bwc.rsnAuthPresharedKeyHex as rsnAuthPresharedKeyHex,
bwc.ipv6Bridging as ipv6Bridging, bwc.priAuth as priAuth, bwc.secAuth as secAuth, bwc.terAuth as terAuth,
bwc.priAcct as priAcct, bwc.secAcct as secAcct, bwc.terAcct as terAcct, bwc.priLdap as priLdap, bwc.secLdap as secLdap,
bwc.terLdap as terLdap, bwc.priLdapIndex as priLdapIndex, bwc.secLdapIndex as secLdapIndex,
bwc.terLdapIndex as terLdapIndex, bwc.localEapAuth as localEapAuth, bwc.eapProfile as eapProfile,
bwc.webPassthruEmail as webPassthruEmail, bwc.ckipSecurity as ckipSecurity, bwc.ckipEncrType as ckipEncrType,
bwc.ckipKeyFormat as ckipKeyFormat, bwc.ckipKeyIndex as ckipKeyIndex, bwc.ckipDefaultKey as ckipDefaultKey,
bwc.ckipMmhMode as ckipMmhMode, bwc.ckipKpEnable as ckipKpEnable, bwc.wlanClientIpv6AclName as wlanClientIpv6AclName,
bwc.globalWebAuth as globalWebAuth, bwc.wlanWebAuthType as wlanWebAuthType,
bwc.wlanWebAuthLoginPage as wlanWebAuthLoginPage, bwc.wlanExternalRedirUrl as wlanExternalRedirUrl,
bwc.wlanWebAuthLoginFailurePage as wlanWebAuthLoginFailurePage, bwc.wlanWebAuthLogoutPage as wlanWebAuthLogoutPage,
bwc.wlanAcctServerEnabled as wlanAcctServerEnabled, bwc.wlanAuthServerEnabled as wlanAuthServerEnabled,
bwc.reapCentralDhcp as reapCentralDhcp, bwc.reapOverrideDns as reapOverrideDns, bwc.ktsCacState as ktsCacState,
bwc.interimUpdate as interimUpdate, bwc.interimUpdateInterval as interimUpdateInterval,
bwc.radiusServerOverwriteInterface as radiusServerOverwriteInterface,
bwc.wifiDirectPolicyStatus as wifiDirectPolicyStatus, bwc.macAuthOrDot1xEnable as macAuthOrDot1xEnable,
bwc.wlanClientDsAverageDataRate as wlanClientDsAverageDataRate,
bwc.wlanClientDsBurstDataRate as wlanClientDsBurstDataRate,
bwc.wlanClientDsAvgRealTimeDataRat as wlanClientDsAvgRealTimeDataRat,
bwc.wlanClientDsBurstRealTimeDatRt as wlanClientDsBurstRealTimeDatRt,
bwc.wlanClientUsAverageDataRate as wlanClientUsAverageDataRate,
bwc.wlanClientUsBurstDataRate as wlanClientUsBurstDataRate,
bwc.wlanClientUsAvgRealTimeDataRat as wlanClientUsAvgRealTimeDataRat,
bwc.wlanClientUsBurstRealTimeDatRt as wlanClientUsBurstRealTimeDatRt,
bwc.wlanSsidUsAverageDataRate as wlanSsidUsAverageDataRate, bwc.wlanSsidUsBurstDataRate as wlanSsidUsBurstDataRate,
bwc.wlanSsidUsAvgRealTimeDataRate as wlanSsidUsAvgRealTimeDataRate,
bwc.wlanSsidUsBurstRealTimeDataRat as wlanSsidUsBurstRealTimeDataRat,
bwc.wlanSsidDsAverageDataRate as wlanSsidDsAverageDataRate, bwc.wlanSsidDsBurstDataRate as wlanSsidDsBurstDataRate,
bwc.wlanSsidDsAvgRealTimeDataRate as wlanSsidDsAvgRealTimeDataRate,
bwc.wlanSsidDsBurstRealTimeDataRat as wlanSsidDsBurstRealTimeDataRat, bwc.ftEnable as ftEnable,
bwc.FTRESASSOCIATIONTIMEOUT as FTRESASSOCIATIONTIMEOUT, bwc.ftOverDs as ftOverDs,
bwc.profilingEnabled as profilingEnabled, bwc.httpProfilingEnabled as httpProfilingEnabled,
bwc.reapWlanVlanCentralSwitching as reapWlanVlanCentralSwitching, bwc.pmipMobilityType as pmipMobilityType,
bwc.pmipWlanProfile as pmipWlanProfile, bwc.pmipWlanRealm as pmipWlanRealm, bwc.reapWlanNatPat as reapWlanNatPat,
bwc.mdnsSnoopingEnabled as mdnsSnoopingEnabled, bwc.mdnsProfileName as mdnsProfileName,
bwc.nbarVisibility as nbarVisibility, bwc.avcProfileName as avcProfileName, bwc.netflowMonitor as netflowMonitor,
bwc.reapWlanAssocCentral as reapWlanAssocCentral, bwc.authentityid as authentityid,
bwc.authentityclass as authentityclass
FROM BaseWlanConfig bwc LEFT JOIN ipaddresstodnsmapping ipdns on bwc.owningEntityId = ipdns.owning_entityId
'''
offset += 5*60.0
# One record for each ProfileName x InterfaceName using the profile
add_table(production, Table(
    'v4', 'data', 'WlanProfiles', True, DAY + offset, 200,  # ***** until bug is fixed
    ('long', '@id'),                    # release 3.x changed string-->long
    ('String', '@displayName', None),   # dupl @id uncommented 2018-07-01
    ('boolean', 'aaaAllowOverride'),    # is allow AAA override?
    ('String', 'aaaLdapPrimaryServer'),  # 1st LDAP server
    ('String', 'aaaLdapSecondaryServer'),  # 2nd LDAP server
    ('String', 'aaaLdapTertiaryServer'),  # 3rd LDAP server
    ('boolean', 'aaaLocalEapAuthenticationEnabled'),  # local EAP authentication?
    ('String', 'aaaLocalEapAuthenticationProfileName', False),  # if so, the profile
    ('String', 'aaaRadiusAccountingPrimaryServer'),
    # The 1st, when aaaRadiusAccountingServersEnabled
    ('String', 'aaaRadiusAccountingSecondaryServer'),
    # The 2nd, when aaaRadiusAccountingServersEnabled
    ('boolean', 'aaaRadiusAccountingServersEnabled'),  # RADIUS accounting?
    ('String', 'aaaRadiusAccountingTertiaryServer'),
    # The 3rd, when aaaRadiusAccountingServersEnabled
    ('String', 'aaaRadiusAuthenticationPrimaryServer'),
    # The 1st, when aaaRadiusAuthorizationServersEnabled
    ('String', 'aaaRadiusAuthenticationSecondaryServer'),
    # The 2nd, when aaaRadiusAuthorizationServersEnabled
    ('boolean', 'aaaRadiusAuthenticationServersEnabled'),  # is RADIUS authorization?
    ('String', 'aaaRadiusAuthenticationTertiaryServer'),
    # The 3rd, when aaaRadiusAuthorizationServersEnabled
    ('boolean', 'aaaRadiusInterimUpdateEnabled'),  # RADIUS server accounting interim update?
    ('smallint', 'aaaRadiusInterimUpdateInterval'),  # ... if so, the update interval in seconds
    ('boolean', 'adminStatus'),         # WLAN administratively enabled?
    ('boolean', 'advancedAironetIeEnabled'),  # Aironet Info Elements enabled for this WLAN?
    ('boolean', 'advancedClientExclusionEnabled'),  # auto client exclusion?
    ('smallint', 'advancedClientExclusionTimeout'),
    # ... if so, timeout in seconds or 0 for infinite
    ('boolean', 'advancedCoverageHoleDetectionEnabled'),  # coverage hole detection?
    ('boolean', 'advancedDhcpAddressAssignmentRequired'),
    # each client required to obtain IP address via DHCP?
    ('boolean', 'advancedDhcpProfilingEnabled'),
    # should the controller collect DHCP attribtes of clients on this WLAN?
    ('String', 'advancedDhcpServerIpAddress_address'),
    # if valid, an IPv4 DHCP server specified for this WLAN
    ('boolean', 'advancedDiagnosticChannelEnabled'),  # diagnostic channel available for this WLAN?
    ('smallint', 'advancedDot11anDtimPeriod'),
    # Delivery Traffic Indication Map (DTIM) for 802.11a/n
    # measured in beacons, during which [broad|multi]cast frames are transmitted
    ('long', 'advancedDot11bgnDtimPeriod'),  # DTIM interval for 802.11b/g/n
    ('boolean', 'advancedFlexConnectCentralDhcpProcessingEnabled'),
    ('boolean', 'advancedFlexConnectLearnClientIpEnabled'),
    ("boolean", "advancedFlexConnectLocalAuthEnabled"),
    ("boolean", "advancedFlexConnectLocalSwitchingEnabled"),
    ("boolean", "advancedFlexConnectNatPatEnabled"),
    ("boolean", "advancedFlexConnectOverrideDnsEnabled"),
    ("boolean", "advancedFlexConnectReapCentralAssociation"),
    ("boolean", "advancedFlexConnectVlanCentralSwitchingEnabled"),
    ("boolean", "advancedHttpProfilingEnabled"),
    ("boolean", "advancedIpv6Enabled"),
    ("boolean", "advancedKtsCacEnabled"),
    ("boolean", "advancedLoadBalancingBandSelectEnabled"),
    ("boolean", "advancedLoadBalancingEnabled"),
    ("smallint", "advancedMaximumClients"),
    ("String", "advancedMdnsProfileName"),
    ("boolean", "advancedMdnsSnoopingEnabled"),
    ("boolean", "advancedMediaSessionSnoopingEnabled"),
    ("DisabledEnabledRequiredEnum", "advancedMfpClientProtection"),
    ("boolean", "advancedMfpSignatureGenerationEnabled"),
    ("smallint", "advancedMfpVersion"),
    ("String", "advancedOverrideInterfaceAclName", False),
    ("String", "advancedOverrideInterfaceIpv6AclName", False),
    ("boolean", "advancedPassiveClientEnabled"),
    ("Peer2PeerBlockingEnum", "advancedPeerToPeerBlocking"),
    ("PmipMobilityTypeEnum", "advancedPmipMobilityType"),
    ("String", "advancedPmipProfile", False),
    ("String", "advancedPmipRealm", False),
    ("boolean", "advancedScanDeferPriority0"),
    ("boolean", "advancedScanDeferPriority1"),
    ("boolean", "advancedScanDeferPriority2"),
    ("boolean", "advancedScanDeferPriority3"),
    ("boolean", "advancedScanDeferPriority4"),
    ("boolean", "advancedScanDeferPriority5"),
    ("boolean", "advancedScanDeferPriority6"),
    ("boolean", "advancedScanDeferPriority7"),
    ("smallint", "advancedScanDeferTime"),
    ("smallint", "advancedSessionTimeout"),
    ("DisabledAllowedNotAllowedEnum", "advancedWifiDirectClientsPolicy"),
    ("boolean", "broadcastSsidEnabled"),
    ("int", "ckipKeyIndex"),
    ("boolean", "ckipKeyPermutationEnabled"),
    ("CkipEncryptionTypeEnum", "ckipKeySize"),
    ("boolean", "ckipMmhModeEnabled"),
    ("boolean", "ckipSecurityEnabled"),
    ("long", "controllerId"),
    ("boolean", "hotspot2Enable_hotSpot2Enabled"),
    ("int", "hotspot2Wan_downLinkSpeed"),
    ("int", "hotspot2Wan_upLinkSpeed"),
    ("WanLinkStatusEnum", "hotspot2Wan_wanLinkStatus"),
    ("WanSymLinkStatusEnum", "hotspot2Wan_wanSymLinkStatus"),
    ("String", "hotspotGeneral_heSsid_octets"),
    ("boolean", "hotspotGeneral_internetAccess"),
    ("IPv4AddressAvailTypeEnum", "hotspotGeneral_ipv4AddressAvailType"),
    ("IPv6AddressAvailTypeEnum", "hotspotGeneral_ipv6AddressAvailType"),
    ("NetworkAuthTypeEnum", "hotspotGeneral_networkAuthType"),
    ("NetworkTypeEnum", "hotspotGeneral_networkType"),
    ("boolean", "hotspotGeneral_status"),  # is 802.11u?
    ("boolean", "hotspotServiceAdvertisement_msapEnable", None),
    ("long", "hotspotServiceAdvertisement_serverIndex", None),
    ("String", "interfaceName"),
    ("InterfaceMappingTypeEnum", "interfaceType"),
    ("String", "ipAddress"),            # Mgt addr of WLAN controller. appeared in 3.6
    ("boolean", "isWiredLan"),
    ("LanTypeEnum", "lanType"),
    ("boolean", "layer2FastTransitionEnabled"),
    ("boolean", "layer2FastTransitionOverDsEnabled"),
    ("smallint", "layer2FastTransitionReassociationTimeout"),
    ("boolean", "layer2MacFilteringEnabled"),
    ("boolean", "layer3GlobalWebAuthEnabled"),
    ("String", "layer3PreauthenticationAcl", False),
    ("String", "layer3PreauthenticationIpv6Acl", False),
    ("boolean", "layer3VpnPassthroughEnabled"),
    ("String", "layer3WebAuthFlexAcl", False),
    ("WlanWebAuthTypeEnum", "layer3WebAuthType"),
    ("boolean", "layer3WebPolicyAuthenticationEnabled"),
    ("boolean", "layer3WebPolicyConditionalRedirectEnabled"),
    ("boolean", "layer3WebPolicyOnMacFailureEnabled"),
    ("boolean", "layer3WebPolicyPassthroughEnabled"),
    ("boolean", "multicastVlanEnabled"),
    ("String", "multicastVlanInterface", False),
    ("String", "profileName"),
    ("PhoneSupport7920Enum", "qos7920Cac"),
    ("String", "qosAvcProfileName"),
    ("boolean", "qosNbarVisibilityEnabled"),
    ("String", "qosNetflowMonitor"),
    ("int", "qosPerSSidBurstRealTimeUpstreamRate"),
    ("int", "qosPerSsidAverageDownstreamRate"),
    ("int", "qosPerSsidAverageRealTimeDownstreamRate"),
    ("int", "qosPerSsidAverageRealTimeUpstreamRate"),
    ("int", "qosPerSsidAverageUpstreamRate"),
    ("int", "qosPerSsidBurstDownstreamRate"),
    ("int", "qosPerSsidBurstRealTimeDownstreamRate"),
    ("int", "qosPerSsidBurstUpstreamRate"),
    ("int", "qosPerUserAverageDownstreamRate"),
    ("int", "qosPerUserAverageRealTimeDownstreamRate"),
    ("int", "qosPerUserAverageRealTimeUpstreamRate"),
    ("int", "qosPerUserAverageUpstreamRate"),
    ("int", "qosPerUserBurstDownstreamRate"),
    ("int", "qosPerUserBurstRealTimeDownstreamRate"),
    ("int", "qosPerUserBurstRealTimeUpstreamRate"),
    ("int", "qosPerUserBurstUpstreamRate"),
    ("QosEnum", "qosProfile"),
    ("DisabledAllowedRequiredEnum", "qosWmmPolicy"),
    ("RadioPolicyEnum", "radioPolicy"),
    ("String", "ssid"),
    ("String", "vpnPassThroughGatewayAddress_address"),
    ("String", "webAuthExternalUrl"),
    ("String", "webAuthLoginFailurePage", False),
    ("String", "webAuthLoginPage", False),
    ("String", "webAuthLogoutPage", False),
    ("boolean", "webPassthruEmailInputEnabled"),
    ("boolean", "wepAllowSharedKeyAuthentication"),
    ("smallint", "wepKeyIndex"),
    ("WepEncryptionTypeEnum", "wepKeySize"),
    ("boolean", "wepSecurityEnabled"),
    ("long", "wlanId"),
    ("boolean", "wpa2Enabled"),
    ("boolean", "wpa2EncryptionProtocolAes"),
    ("boolean", "wpa2EncryptionProtocolTkip"),
    ("boolean", "wpaAuthenticationKeyManagement8021x"),
    ("boolean", "wpaAuthenticationKeyManagementCckm"),
    ("boolean", "wpaAuthenticationKeyManagementFt8021x"),
    ("boolean", "wpaAuthenticationKeyManagementFtPsk"),
    ("boolean", "wpaAuthenticationKeyManagementPmf8021x"),
    ("boolean", "wpaAuthenticationKeyManagementPmfPsk"),
    ("boolean", "wpaAuthenticationKeyManagementPsk"),
    ("boolean", "wpaEnabled"),
    ("boolean", "wpaEncryptionProtocolAes"),
    ("boolean", "wpaEncryptionProtocolTkip"),
    ("String", "wpaPresharedKey"),      # appeared in 3.6
    ("PskFormatEnum", "wpaPresharedKeyFormat"),  # appeared in 3.6
    ("boolean", "wpaSecurityEnabled"),
    ("x8021EncryptionTypeEnum", "x8021KeySize"),
    ("boolean", "x8021SecurityEnabled")
)
          # ignore this subtable, because we don't have hot spots
          .subTable("hotspot2Operators", [("float", "polledTime"), ("long", "@id")],
                    ("smallint", "operatorId", False),
                    ("String", "operatorLang", False),
                    ("String", "operatorName", False)
                    )
          # ignore this subtable, because we don't have hot spots
          .subTable("hotspot2Ports", [("float", "polledTime"), ("long", "@id")],
                    ("smallint", "portConfigId", False),
                    ("PortNoEnum", "portNo", False),
                    ("PortStatusEnum", "portStatus", False),
                    ("ProtocolNameEnum", "protocolName", False)
                    )
          # ignore this subtable, because we don't have hot spots
          .subTable("hotspotCellularNetworks", [("float", "polledTime"), ("long", "@id")],
                    ("String", "countryCode", False),
                    ("smallint", "gppIndex", False),
                    ("String", "networkCode", False)
                    )
          # ignore this subtable, because we don't have hotspots
          .subTable("hotspotDomains", [("float", "polledTime"), ("long", "@id")],
                    ("int", "domainId", False),
                    ("String", "domainName", False)
                    )
          # ignore this subtable, because we don't have hotspots
          .subTable("hotspotOuiConfigs", [("float", "polledTime"), ("long", "@id")],
                    ("String", "oui", False),
                    ("String", "ouiId", False),
                    ("boolean", "ouiInBeacon", False)
                    )
          # ignore this subtable, because we don't have hotspots
          .subTable("hotspotRealms", [("float", "polledTime"), ("long", "@id")],
                    ("int", "realmId", False),
                    ("String", "realmName", False)
                    )
          .subTable("hotspotRealms_realmEapMethods",
                    [("float", "polledTime"), ("long", "@id"), ("int", "realmId")],
                    ("int", "realmEapId", False),
                    ("RealmEapMethodEnum", "realmEapMethod", False),
                    ("RealmEapMethodEnum", "realmEapMethod", False)
                    )
          .subTable("hotspotRealms_realmEapMethods_innerAuthMethods",
                    [("float", "polledTime"), ("long", "@id"), ("int", "realmId"), ("int", "realmEapId")],
                    ("int", "realmEapAuthId", False),
                    ("RealmEapAuthMethodEnum", "realmEapAuthMethod", False),
                    ("RealmEapAuthParamEnum", "realmEapAuthParam", False)
                    )
          .set_id_field("@id")
          # .set_paged(False)			# ***** Workaround for CPI internal error
          .set_query_options({".full": "true", ".nocount": "true"})
          )

# O L D   T A B L E   D E F I N I T I O N S

add_table(archive, Table(
    "v2", "data", "ClientSessions", False, DAY + 3*HOUR, 8000,
    ("String", "@id"),
    ("String", "@displayName"),         # copy of @id uncommented 2018-07-01
    ("String", "adDomainName"),         # AD domain from ISE; blank in v2
    ("String", "anchorIpAddress"),      # of mobility anchor controller, or 0.0.0.0
    ("String", "apIpAddress", False),   # doc but not in v1, undoc in v3; reappeared in v3.4
    ("String", "apMacAddress"),         # Associated AP MAC address
    ("String", "apName", False),        # doc but not in v1. undoc in v3; reappeared in v3.4
    ("AuthenticationAlgorithmEnum", "authenticationAlgorithm"),
    ("String", "authorizationPolicy"),  # from ISE; doc but not present in v1
    ("long", "bytesReceived"),          # cumulative bytes received during this session
    ("long", "bytesSent"),              # cumulative bytes sent during this session
    ("String", "clientInterface"),      # {case[auth|guest]*, ic-inside, management}
    ("ConnectionTypeEnum", "connectionType"),
    ("String", "ctsSecurityGroup"),     # from ISE; currently not present
    ("String", "deviceIpAddress"),      # controller IP address
    ("String", "deviceName"),           # controller or switch name
    ("EapTypeEnum", "eapType"),
    ("EncryptionCypherEnum", "encryptionCypher"),  # Client cypher
    # ("String", "instanceUuid"),	    # originally doc, but removed in v1
    ("String", "ipAddress"),            # Client IP address
    ("ClientIpTypeEnum", "ipType"),
    ("String", "location"),             # campus > building > floor
    ("String", "macAddress"),           # Client MAC
    ("long", "packetsReceived"),        # cumulative received in this session
    ("long", "packetsSent"),            # cumulative sent in this session
    ("PolicyTypeStatusEnum", "policyTypeStatus"),  # Client policy status
    ("ClientSpeedEnum", "portSpeed"),
    ("PostureStatusEnum", "postureStatus"),
    ("String", "profileName"),          # WLAN Profile Name
    ("ClientProtocolEnum", "protocol"),
    ("String", "roamReason"),           # not present in v1
    ("smallint", "rssi"),               # RSSI (dBm) from last polling
    ("SecurityPolicyEnum", "securityPolicy"),  # Client
    ("epochMillis", "sessionEndTime"),  # time the session finished, or future
    ("epochMillis", "sessionStartTime"),  # time the session started
    ("smallint", "snr"),                # from last polling during the session
    ("String", "ssid"),                 # SSID
    ("double", "throughput"),           # session Avg. Blank while session open
    ("String", "userName"),             # Client username
    ("String", "vlan"),                 # vlan name
    ("WebSecurityEnum", "webSecurity"),  # is client auth via WebAuth?
    ("String", "wgbMacAddress"),        # WorkGroup Bridge MAC, or 00:00:00:00:00:00:00
    ("WGBStatusEnum", "wgbStatus")      # Client type
).set_id_field("@id")
          .set_query_options({".full": "true", ".nocount": "true"})
          .set_pager('cs_pager')
          )

add_table(archive, Table(
    "v4", "data", "HistoricalClientCounts", False, 1, 120000,
    ("String", "@id"),
    ("String", "@displayName"),         # copy of @id uncommented 2018-07-01
    ("smallint", "authCount"),          # as of last collection time
    ("epochMillis", "collectionTime"),  # Epoch millis when record was collected
    ("smallint", "count"),              # total client count
    ("smallint", "dot11aAuthCount"),
    ("smallint", "dot11aCount"),
    ("smallint", "dot11acAuthCount"),
    ("smallint", "dot11acCount"),
    ("smallint", "dot11bAuthCount"),
    ("smallint", "dot11bCount"),
    ("smallint", "dot11gAuthCount"),
    ("smallint", "dot11gCount"),
    ("smallint", "dot11n2_4AuthCount"),
    ("smallint", "dot11n2_4Count"),
    ("smallint", "dot11n5AuthCount"),
    ("smallint", "dot11n5Count"),
    # ("String", "instanceUuid"),	    # originally doc, but undoc from v1
    ("String", "key"),
    ("String", "subkey"),
    # for type=ACCESSPOINT; subkey is {"All", enum(SSIDs)}; key is an apMac
    # for type=DEVICE; subkey is {"All", enum(SSIDs)}; key is controller Ip
    # for type=MAPLOCATION; subkey is {"All", enum(SSIDs)}; key is a GroupSpecification.groupName
    # data is useless because e.g. "Floor 1" is repeated w/o qualification
    # for type=SSID; subkey is {virtual domain, "ROOT-DOMAIN"}; key is {"All SSIDs", enum(SSIDs)}
    # subkeys repeat multiple times. all data=0 except for ROOT-DOMAIN
    # for type=VIRTUALDOMAIN; subkey is All; key is virtualDomain [All Autonomous APs|All SSIDs|All wired|All Wireless]
    # similarly, the keys repeat multiple times, and all data=0 except for ROOT-DOMAIN - [|All Wireless|All SSIDs]
    ("ClientCountTypeEnum", "type"),
    ("smallint", "wgbAuthCount"),       # clients auth as WGB or wired guest
    ("smallint", "wgbCount"),           # clients connected as WorkGroup Bridge or wired guest
    ("smallint", "wired100MAuthCount"),
    ("smallint", "wired100MCount"),
    ("smallint", "wired10GAuthCount", False),  # appeared in 3.6
    ("smallint", "wired10GCount", False),  # appeared in 3.6
    ("smallint", "wired10MAuthCount"),
    ("smallint", "wired10MCount"),
    ("smallint", "wired1GAuthCount"),
    ("smallint", "wired1GCount")
    # ("String", "adminStatus")		    # undoc field appeared in 2017-02-16, then undoc
).set_id_field("@id").set_time_field("collectionTime")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

add_table(archive, Table(
    "v1", "data", "HistoricalClientCountsV0", False, 1, 120000,
    ("String", "@id"),
    ("String", "@displayName"),         # copy of @id
    ("smallint", "authCount"),
    ("epochMillis", "collectionTime"),  # millis
    ("smallint", "count"),
    ("smallint", "dot11aAuthCount"),
    ("smallint", "dot11aCount"),
    ("smallint", "dot11acAuthCount"),
    ("smallint", "dot11acCount"),
    ("smallint", "dot11bAuthCount"),
    ("smallint", "dot11bCount"),
    ("smallint", "dot11gAuthCount"),
    ("smallint", "dot11gCount"),
    ("smallint", "dot11n2_4AuthCount"),
    ("smallint", "dot11n2_4Count"),
    ("smallint", "dot11n5AuthCount"),
    ("smallint", "dot11n5Count"),
    ("String", "instanceUuid"),
    ("String", "key"),                  # byType {MAC, IP address, "All Guest", text, SSID, text}
    ("String", "subkey"),               # byType{SSID, "All"||SSID, "GUEST", SSID, map text, "All"}
    ("ClientCountTypeEnum", "type"),
    ("smallint", "wgbAuthCount"),
    ("smallint", "wgbCount"),
    ("smallint", "wired100MAuthCount"),
    ("smallint", "wired100MCount"),
    ("smallint", "wired10MAuthCount"),
    ("smallint", "wired10MCount"),
    ("smallint", "wired1GAuthCount"),
    ("smallint", "wired1GCount")
).set_id_field("@id").set_time_field("collectionTime")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

add_table(archive, Table(
    "v2", "data", "HistoricalClientTraffics", False, 1, 40000,
    ("String", "@id"),
    ("String", "@displayName", False),  # copy of @id uncommented 2018-07-01
    # ("String", "@uuid"),			    # blank
    ("epochMillis", "collectionTime"),  # millis
    ("String", "dot11aReceived"),       # cumulative bytes received
    ("long", "dot11aSent"),             # cumulative bytes sent
    ("long", "dot11aThroughput"),       # cumulative throughput in Kbps
    ("long", "dot11acReceived"),        # cumulative bytes received
    ("long", "dot11acSent"),            # cumulative bytes sent
    ("long", "dot11acThroughput"),      # total throughput in Kbps
    ("String", "dot11bReceived"),       # cumulative bytes received
    ("long", "dot11bSent"),             # cumulative bytes sent
    ("long", "dot11bThroughput"),       # cumulative throughput in Kbps
    ("String", "dot11gReceived"),       # cumulative bytes received
    ("long", "dot11gSent"),             # cumulative bytes sent
    ("long", "dot11gThroughput"),       # total throughput in Kbps
    ("String", "dot11n2_4Received"),    # cumulative bytes received
    ("long", "dot11n2_4Sent"),          # cumulative bytes sent
    ("long", "dot11n2_4Throughput"),    # total throughput in Kbps
    ("String", "dot11n5Received"),      # cumulative bytes received
    ("long", "dot11n5Sent"),            # cumulative bytes sent
    ("long", "dot11n5Throughput"),      # cumulative throughput in Kbps
    # ("String", "instanceUuid"),	    # originally doc. undoc in v1.x
    ("String", "key"),      # byType {MAC, IP address, "All Guest", text, SSID, text}
    ("String", "received"),             # total bytes received
    ("long", "sent"),                   # total bytes sent
    ("String", "subkey"),               # depends on type:
    # for type=ACCESSPOINT; subkey is {"All", enum(SSIDs)}; key is an apMac
    # for type=DEVICE; subkey is {"All", enum(SSIDs)}; key is controller Ip
    # for type=MAPLOCATION; subkey is {"All", enum(SSIDs)}; key is a GroupSpecification.groupName
    # data is useless because e.g. "Floor 1" is repeated w/o qualification
    # for type=SSID; subkey is {virtual domain, "ROOT-DOMAIN"}; key is {"All SSIDs", enum(SSIDs)}
    # subkeys repeat multiple times. all data=0 except for ROOT-DOMAIN
    # for type=VIRTUALDOMAIN; subkey is All; key is virtualDomain [All Autonomous APs|All SSIDs|All wired|All Wireless]
    # similarly, the keys repeat multiple times, and all data=0 except for ROOT-DOMAIN - [|All Wireless|All SSIDs]
    ("long", "throughput"),             # total throughput in Kbps
    ("ClientCountTypeEnum", "type"),
    ("String", "wired100MReceived"),    # 0
    ("long", "wired100MSent"),          # 0
    ("long", "wired100MThroughput"),    # 0
    ("String", "wired10GReceived", False),  # appeared in 3.6
    ("long", "wired10GSent", False),    # appeared in 3.6
    ("long", "wired10GThroughput"),     # appeared in 3.6
    ("String", "wired10MReceived"),     # 0
    ("long", "wired10MSent"),           # 0
    ("long", "wired10MThroughput"),     # 0
    ("String", "wired1GReceived"),      # 0
    ("long", "wired1GSent"),            # 0
    ("long", "wired1GThroughput")       # 0
).set_id_field("@id").set_time_field("collectionTime")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

# statistics are during this session
add_table(archive, Table(
    "v2", "data", "HistoricalClientStats", False, 1, 16000,
    ("String", "@id"),                  # Session id
    ("String", "@displayName", False),  # copy of @id uncommented 2018-07-01
    ("long", "bytesReceived"),          # cumulative bytes received
    ("long", "bytesSent"),              # cumulative bytes sent
    ("epochMillis", "collectionTime"),  # Unix epoch millis
    ("float", "dataRate"),              # reading data rate Mbps
    ("long", "dataRetries"),            # cumulative data Retries
    # ("String", "instanceUuid"),	    # originally doc. removed in v1
    ("String", "macAddress"),           # client MAC
    ("long", "packetsReceived"),        # cumulative packets received
    ("long", "packetsSent"),            # cumulative packets Sent
    ("long", "raPacketsDropped"),       # cumulative IPv6 RA packets dropped
    ("smallint", "rssi"),               # RSSI (dBm) as measured by AP
    ("long", "rtsRetries"),             # cumulative RTS Retries
    ("long", "rxBytesDropped"),         # cumulative rx Bytes dropped
    ("long", "rxPacketsDropped"),       # cumulative rx Packets dropped
    ("smallint", "snr"),                # SNR as measured by the AP
    ("long", "txBytesDropped"),         # cumulative tx Bytes dropped
    ("long", "txPacketsDropped")        # cumulative tx Packets dropped
).set_id_field("@id").set_time_field("collectionTime")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

# each count is total for all time.
add_table(archive, Table(
    "v2", "data", "HistoricalRFCounters", False, 1, 4*2*NUMAP,
    ("String", "@id"),
    ("String", "@displayName", False),  # copy of @id uncommented 2018-07-01
    ("long", "ackFailureCount"),        # cumulative count of ACK failures
    ("DateBad", "collectionTime"),      # epoch millis that collection finished
    ("long", "failedCount"),            # cumulative count of Failures
    ("long", "fcsErrorCount"),          # cumulative count of Errors
    ("long", "frameDuplicateCount"),
    # ("String", "instanceUuid"),	    # originally present, but removed in v1x
    ("String", "macAddress"),           # Base radio MAC
    ("long", "multipleRetryCount"),     # cumulative count of Multiple Retries
    ("long", "retryCount"),             # cumulative count of Retries
    ("long", "rtsFailureCount"),        # cumulative count of RTS Railures
    ("long", "rtsSuccessCount"),        # cumulative count of RTS Successes
    ("long", "rxFragmentCount"),        # cumulative count of rx fragments
    ("long", "rxMulticastFrameCount"),  # cumulative of rx Multicast frames
    ("String", "slotId"),               # [0:1]
    ("long", "txFragmentCount"),        # cumulative count of tx Fragments
    ("long", "txFrameCount"),           # cumulative count of tx Frames
    ("long", "txMulticastFrameCount"),  # cumulative of tx Multicast frames
    ("long", "wepUndecryptableCount")   # cumulative of undecryptable WEP
).set_id_field("@id").set_time_field("collectionTime")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

add_table(archive, Table(
    "v2", "data", "HistoricalRFStats", False, 1, 4*2*NUMAP,
    ("String", "@id"),
    ("String", "@displayName", False),  # copy of @id uncommented 2018-07-01
    ("ChannelNumberEnum", "channelNumber"),
    ("smallint", "channelUtilization"),  # percent [0:100]
    ("smallint", "clientCount"),        # number of associated clients
    ("String", "collectionTime"),       # Unix epoch millis
    ("RFProfileEnum", "coverageProfile"),
    ("String", "ethernetMac"),          # AP MAC address
    # ("String", "instanceUuid"),	    # originally doc. but dropped in v1.
    ("RFProfileEnum", "interferenceProfile"),
    ("RFProfileEnum", "loadProfile"),
    ("String", "macAddress"),           # base radio MAC
    ("RFProfileEnum", "noiseProfile"),
    ("RadioOperStatusEnum", "operStatus"),
    ("smallint", "poorCoverageClients"),  # Count?
    ("smallint", "powerLevel"),         # [1:8]
    ("smallint", "rxUtilization"),      # percent [0:100]
    ("String", "slotId"),               # [0|1]
    ("smallint", "txUtilization"),      # percent [0:100]
).set_id_field("@id").set_time_field("collectionTime")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

add_table(archive, Table(
    "v2", "data", "AccessPointDetails", True, HOUR*8, 10000,
    ("String", "@id"),                  # Access Point id
    ("String", "@displayName", False),  # duplicates @id uncommented 2018-07-01
    ("ApAdminStatusEnum", "adminStatus"),
    ("String", "apType"),               # AP type
    # autonomousAP and cdpNeighbors are defined as array of objects. may be:
    # 	totally absent
    # 	present as a single object with individual components
    # 	present as array of objects with individual components
    # Ignore such embedded arrays in this pure relational model
    ("String", "cdpNeighbors_cdpNeighbor_capabilities", False),
    ("String", "cdpNeighbors_cdpNeighbor_duplex", False),
    ("String", "cdpNeighbors_cdpNeighbor_interfaceSpeed", False),
    ("String", "cdpNeighbors_cdpNeighbor_localPort", False),
    ("String", "cdpNeighbors_cdpNeighbor_neighborIpAddress", False),
    ("String", "cdpNeighbors_cdpNeighbor_neighborName", False),
    ("String", "cdpNeighbors_cdpNeighbor_neighborPort", False),
    ("String", "cdpNeighbors_cdpNeighbor_platform", False),
    ("String", "clientCount"),          # doc as String, but delivered as NUMBER
    ("String", "clientCount_2_4GHz"),   # doc as String, but delivered as NUMBER
    ("smallint", "clientCount_5GHz"),
    ("String", "ethernetMac"),          # AP MAC
    # ("String", "instanceUuid"), 	    # originally doc but not present in v1
    ("String", "ipAddress"),            # AP IP address
    ("String", "locationHeirarchy"),    # map location entire hierarchy
    ("String", "macAddress"),           # base radio MAC
    ("String", "mapLocation"),          # SNMP location?
    ("String", "model"),                # AP model
    ("String", "name"),                 # AP name
    ("ReachabilityStateEnum", "reachabilityStatus"),  # [not present]
    ("String", "serialNumber"),
    ("String", "softwareVersion"),
    ("AlarmSeverityEnum", "status"),
    ("String", "type"),                 # {CAPWAP, Autonomous, UnifiedAp}
    ("smallint", "unifiedApInfo_instanceId"),  # not present
    ("long", "unifiedApInfo_instanceVersion"),  # not present
    ("smallint", "unifiedApInfo_apCertType"),
    ("String", "unifiedApInfo_apGroupName"),
    ("String", "unifiedApInfo_apMode"),  # doc as String but delivered as NUMBER
    ("smallint", "unifiedApInfo_apStaticEnabled"),
    ("String", "unifiedApInfo_bootVersion"),
    ("long", "unifiedApInfo_capwapJoinTakenTime"),
    ("long", "unifiedApInfo_capwapUpTime"),
    ("String", "unifiedApInfo_controllerIpAddress"),
    ("String", "unifiedApInfo_controllerName"),
    ("String", "unifiedApInfo_contryCode"),  # misspelled ...contry...
    ("boolean", "unifiedApInfo_encryptionEnabled"),
    ("String", "unifiedApInfo_flexConnectGroupName"),  # not present
    ("boolean", "unifiedApInfo_flexConnectMode"),
    ("String", "unifiedApInfo_iosVersion"),
    ("boolean", "unifiedApInfo_linkLatencyEnabled"),
    ("MeshRoleEnum", "unifiedApInfo_lradMeshNode_meshRole", False),  # appeared in 2018-06-24
    ("String", "unifiedApInfo_maintenanceMode", False),  # appeared in 2018-06-24
    ("PoeStatusEnumInt", "unifiedApInfo_poeStatus"),  # doc as String, but NUMBER
    ("String", "unifiedApInfo_poeStatusEnum"),
    # {LOW, FIFTEENDOTFOUR, SIXTEENDOTEIGHT, NORMAL, EXTERNAL, MIXEDMODE}
    ("smallint", "unifiedApInfo_portNumber"),
    ("smallint", "unifiedApInfo_powerInjectorState"),
    ("smallint", "unifiedApInfo_preStandardState"),
    ("String", "unifiedApInfo_primaryMwar"),
    ("boolean", "unifiedApInfo_rogueDetectionEnabled"),
    ("String", "unifiedApInfo_secondaryMwar"),  # not present
    ("boolean", "unifiedApInfo_sshEnabled"),
    ("int", "unifiedApInfo_statisticsTimer"),
    ("boolean", "unifiedApInfo_telnetEnabled"),
    ("String", "unifiedApInfo_tertiaryMwar"),  # not present
    ("boolean", "unifiedApInfo_vlanEnabled"),  # not present -- no FlexConnect
    ("long", "unifiedApInfo_vlanNativeId"),
    ("long", "unifiedApInfo_WIPSEnabled"),
    # array
    ("ignore", "unifiedApInfo_wlanProfiles", False),  # appeared after 2017-02-16 software upgrade
    ("ignore", "unifiedApInfo_wlanProfiles_wlanProfile", False),
    # new Array object in 2017-02-16 upgrade
    ("ignore", "unifiedApInfo_wlanProfiles_wlanProfile_broadcastSsidEnabled", False),
    # new Array after 2017-02-16 upgrade
    ("ignore", "unifiedApInfo_wlanProfiles_wlanProfile_profileName", False),
    # new Array after 2017-02-16 upgrade
    ("ignore", "unifiedApInfo_wlanProfiles_wlanProfile_ssid", False),
    # new Array after 2017-02-16 upgrade
    # ("ignore", "unifiedApInfo_wlanProfiles_broadcastSsidEnabled", False),
    # ("ignore", "unifiedApInfo_wlanProfiles_profileName", False),
    # ("ignore", "unifiedApInfo_wlanProfiles_ssid", False),
    # *** doc as compound structure(String ssid, long vlanId, long wlanId) but delivered as None string
    ("ignore", "unifiedApInfo_wlanVlanMappings", False),
    ("long", "upTime")                  # millis
).set_id_field("@id")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

add_table(archive, Table(
    "v2", "data", "ClientDetails", True, 8*HOUR, 70000,
    ("String", "@id"),
    ("String", "@displayName", False),  # dupl @id. uncommented 2018-07-01
    ("String", "adDomainName"),         # AD domain acquired from ISE
    ("String", "apIpAddress_address"),  # associated AP IP address
    ("String", "apMacAddress"),         # associated AP MAC address
    ("String", "apName"),               # associated AP name
    ("smallint", "apSlotId"),           # associated AP slot ID
    ("epochMillis", "associationTime"),  # current or last session start time
    ("String", "auditSessionId"),       # Client audit session ID
    ("AuthenticationAlgorithmEnum", "authenticationAlgorithm"),  # client's auth alg
    ("String", "authnTimeStamp"),       # acquired from ISE
    ("String", "authorizationPolicy"),  # acquired from ISE
    ("String", "authorizedBy"),         # Authorization provider
    # ("long", "bytesReceived"),	    # only present in v1
    # ("long", "bytesSent"),   		    # only present in v1
    ("CcxFSVersionEnum", "ccxFSVersion"),  # client card version v2
    ("CcxFSVersionEnum", "ccxLSVersion"),  # client card version v2
    ("CcxFSVersionEnum", "ccxMSVersion"),  # client card version v2
    ("CcxFSVersionEnum", "ccxVSVersion"),  # client card version v2
    ("CCXVersionEnum", "ccxVersion"),  # client card version
    ("ClientAclAppliedEnum", "clientAaaOverrideAclApplied"),  # AA override applied?
    ("String", "clientAaaOverrideAclName"),  # ACL name
    ("ClientAclAppliedEnum", "clientAclApplied"),  # ACL applied to client v2
    ("String", "clientAclName"),        # ACL name applied to the client
    ("ClientApModeEnum", "clientApMode"),  #
    ("String", "clientInterface"),      # interface LAN
    ("String", "clientRedirectUrl"),    # Redirect URL applied to the client
    ("ConnectionTypeEnum", "connectionType"),  # from ISE
    ("String", "ctsSecurityGroup"),
    ("String", "deviceIpAddress_address"),  # of assoc controller or switch
    ("String", "deviceName"),           # name of assoc controller or switch
    ("String", "deviceType"),           # Client device type acquired from ISE
    ("EapTypeEnum", "eapType"),
    ("EncryptionCypherEnum", "encryptionCypher"),  # Client encrpyt. cypher
    ("String", "failureCode"),          # from ISE
    ("String", "failureStep"),          # from ISE
    ("epochMillis", "firstSeenTime"),   # time client was first discovered
    ("String", "hostname"),             # reverse DNS from client IP address
    ("long", "hreapLocallyAuthenticated"),  # authenticated via HREAP?
    ("String", "ifDescr"),              # SNMP ifDescr of the connected switch
    ("smallint", "ifIndex"),            # SNMP ifIndex of the connected switch
    # ("String", "instanceUUid"),	    # not in the doc, but present in v2.
    ("String", "ipAddress_address"),    # Client IP address
    ("ClientIpTypeEnum", "ipType"),     # Client IP type
    ("String", "iseName"),              # ISE name which the client is reported
    ("String", "location"),             # Map location hierarchy
    ("String", "macAddress"),           # Client MAC address
    ("MobilityStatusEnum", "mobilityStatus"),  # Client mobility status
    ("NACStateEnum", "nacState"),       # Client NAC state
    # ("long", "packetsReceived"),	    # only in v1
    # ("long", "packetsSent"),		    # only in v1
    ("SecurityPolicyEnum", "policyType"),  # v2
    ("PolicyTypeStatusEnum", "policyTypeStatus"),  # Client from ISE
    ("PostureStatusEnum", "postureStatus"),  # Client from ISE
    ("ClientProtocolEnum", "protocol"),  # [last] connection protocol
    # ("smallint", "rssi"),			    # only in v1
    ("String", "radiusResponse"),       # from ISE
    ("SecurityPolicyStatusEnum", "securityPolicyStatus"),  # Client on network?
    # ("smallint", "snr"),			    # only in v1
    ("ClientSpeedEnum", "speed"),       # wired port speed or UNKNOWN for wireless
    ("String", "ssid"),                 # [last] SSID
    ("ClientStatusEnum", "status"),     # Client connection
    # ("double", "throughput"),		    # only in v1
    # ("long", "traffic"),			    # only in v1
    ("long", "updateTime"),             # last epoch millis  record was updated
    ("String", "userName"),             # Client username
    ("String", "vendor"),               # Vendor name of the client NIC from OUI mapping
    ("String", "vlan"),                 # VLAN ID doc as String, but JSON is NUMBER
    ("String", "vlanName"),             # [blank] name of the VLAN
    ("WebSecurityEnum", "webSecurity"),  # client is authenticated by WebAuth
    ("WepStateEnum", "wepState"),
    ("String", "wgbMacAddress"),        # if client is a WorkGroup Bridge
    ("WGBStatusEnum", "wgbStatus"),     # Client WorkGroup Bridge status
    ("WiredClientTypeEnum", "wiredClientType")
).set_id_field("@id")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

# Information is not useful, cease polling
# one record for each Controller in the inventory
offset += 5*60.0
add_table(archive, Table(
    "v2", "data", "ConfigArchives", True, DAY + offset, 10000,
    ("String", "@id"),
    ("String", "@displayName", False),  # duplicate of @id
    ("String", "deviceIpAddress"),      # Controller IP
    ("String", "deviceName"),           # Controller host name
    # ("String", "instanceUuid"),	    # originally doc, but not present in v1
    ("String", "lastMessage"),          # error message, if last collection failed
    ("boolean", "lastSuccessful")       # result of last collection
).set_id_field("@id")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

offset += 5*60.0
add_table(archive, Table(
    "v2", "data", "Devices", True, DAY + offset, 10000,
    ("long", "@id", False),             # uncommented 2018-07-01
    ("String", "@displayName", False),  # duplicates @id uncommented 2018-07-01
    ("String", "adminStatus"),          # added by 2017-02-16 software upgrade
    ("smallint", "clearedAlarms"),      # removed in v3
    ("String", "collectionDetail"),     # html string
    # ("String", "collectionStatus")
    # not present in v1 -- {[MAJOR]COMPLETED, [PARTIAL]COLLECTIONFAILURE,
    # SNMPCONNECTIVITYFAILED, WRONG[HTTP]CREDENTIALS, [MAJOR|MINOR|]SYNCHRONIZING,
    # SNMPUSERAUTHENTIFICATIONFAILED, NOLICENSE, ADDINITIATED,
    # DELETEINPROGRESS, PINGUNREACHIBLE, SPT_ONLY, IN_SERVICE[_MAINTENANCE]}
    ("String", "collectionTime"),       # Instant
    ("String", "creationTime"),         # Instant
    ("smallint", "criticalAlarms"),
    ("long", "deviceId"),               # delivered as a number in v1
    ("String", "deviceName"),
    ("String", "deviceType"),
    ("smallint", "informationAlarms"),  # removed in v3
    # ("String", "instanceUuid"),	    # originally doc, but not present in v1.
    ("String", "ipAddress"),
    ("String", "location"),
    ("smallint", "majorAlarms"),        # removed in v3
    ("LifecycleStateEnum", "managementStatus"),  #
    ("smallint", "minorAlarms"),        # removed in v3
    # (StringArray.class, "manufacturerPartNr")# new in v2, but doesn't fit relational
    ("String", "productFamily"),
    ("ReachabilityStateEnum", "reachability"),
    ("String", "softwareType"),
    ("String", "softwareVersion"),
    ("smallint", "warningAlarms")       # removed in v3
).set_id_field("@id")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

offset += 5*60.0
add_table(archive, Table(
    "v1", "data", "Devices", True, DAY + offset, 10000,
    ("String", "@id"),
    ("String", "@displayName"),
    ("smallint", "clearedAlarms"),
    ("String", "collectionDetail"),
    ("instant", "collectionTime"),
    ("instant", "creationTime"),
    ("smallint", "criticalAlarms"),
    ("long", "deviceId"),
    ("String", "deviceName"),
    ("String", "deviceType"),
    ("smallint", "informationAlarms"),
    ("String", "instanceUuid"),
    ("String", "ipAddress"),
    ("String", "location"),
    ("smallint", "majorAlarms"),
    ("LifecycleStateEnum", "managementStatus"),
    ("smallint", "minorAlarms"),
    ("String", "productFamily"),
    ("ReachabilityStateEnum", "reachability"),
    ("String", "softwareType"),
    ("String", "softwareVersion"),
    ("smallint", "warningAlarms")
).set_id_field("@id")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

# Radio details that are not in "Historical" data
# one record per radio
offset += 5*60.0
add_table(archive, Table(
    "v2", "data", "RadioDetails", True, DAY + offset, 2*NUMAP,
    ("String", "@id"),
    ("String", "@displayName", False),  # copy of @id uncommented 2018-07-01
    ("RadioAdminStatusEnum", "adminStatus"),
    ("AlarmSeverityEnum", "alarmStatus"),
    ("float", "antennaAzimAngle"),      # horizontal antenna angle in degrees
    ("String", "antennaDiversity"),     # antenna diversity? enum{Connector A, Enabled}
    ("float", "antennaElevAngle"),      # elevation angle in degrees
    ("smallint", "antennaGain"),        # external gain in 2*dBm. e.g. 7 --> 3.5dBm
    ("String", "antennaMode"),          # enum {Omni, Directional, NA}
    ("String", "antennaName"),          # antenna part-no
    ("String", "antennaType"),          # Internal or External
    ("String", "apIpAddress"),          # of the access point; blank if {DOWN}
    ("String", "apName"),               # name of the AP
    ("String", "baseRadioMac"),         # MAC of the base radio
    ("String", "channelControl"),       # enum{Automatic, Custom}
    ("smallint", "channelNumber"),      # int, not enum
    ("String", "channelWidth"),         # enum{"20 MHz", "Above 40MHz", "NA"}
    ("String", "cleanAirCapable"),      # enum{No, Yes}
    ("String", "cleanAirSensorStatus"),  # enum{Down, NA, Up}
    ("String", "cleanAirStatus"),       # enum{No, Yes}
    ("String", "clientCount"),          # clients connected to the radio interface
    ("String", "controllerIpAddress"),  # for CAPWAP AP only
    ("boolean", "dot11nCapable"),       # enum{TRUE, FALSE}
    ("String", "ethernetMac"),          # MAC of the ethernet address on the AP
    # ("String", "instanceUuid"),	    # originally doc, but undoc in v1
    ("RadioOperStatusEnum", "operStatus"),
    ("smallint", "port"),               # controller port number
    ("smallint", "powerLevel"),         # power level of the radio [0:8]
    ("RadioBandEnum", "radioBand", False),  # appeared in 3.6
    ("RadioRoleEnum", "radioRole"),
    ("String", "radioType"),            # enum{"801.11[a|a/n|a/n/ac|b/g|b/g/n]"}
    ("smallint", "slotId"),             # [0:1]
    ("String", "txPowerControl"),       # enum{Automatic, Custom}
    ("smallint", "txPowerOutput")       # in dBm. appeared in 2017-02-16 upgrade
).set_id_field("@id")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

offset += 5*60.0
# one record per radio
add_table(archive, Table(
    "v1", "data", "RadioDetailsV0", True, DAY + offset, 2*NUMAP,
    ("String", "@id"),
    ("String", "@displayName"),         # copy of @id
    ("RadioAdminStatusEnum", "adminStatus"),
    ("AlarmSeverityEnum", "alarmStatus"),
    ("float", "antennaAzimAngle"),
    ("String", "antennaDiversity"),
    ("float", "antennaElevAngle"),
    ("smallint", "antennaGain"),
    ("String", "antennaMode"),
    ("String", "antennaName"),
    ("String", "antennaType"),
    ("String", "apIpAddress"),          # AP IP address; blank if {DOWN}
    ("String", "apName"),
    ("String", "baseRadioMac"),         # MAC
    ("String", "channelControl"),       # enum{Automatic, Custom}
    ("smallint", "channelNumber"),      # int, not enum
    ("String", "channelWidth"),         # enum{"20 MHz", "Above 40MHz", "NA"}
    ("String", "cleanAirCapable"),      # enum{No, Yes}
    ("String", "cleanAirSensorStatus"),  # enum{Down, NA, Up}
    ("String", "cleanAirStatus"),       # enum{No, Yes}
    ("String", "clientCount"),
    ("String", "controllerIpAddress"),
    ("boolean", "dot11nCapable"),       # enum{TRUE, FALSE}
    ("String", "ethernetMac"),          # MAC
    ("String", "instanceUuid"),
    ("RadioOperStatusEnum", "operStatus"),
    ("smallint", "port"),               # controller port number
    ("smallint", "powerLevel"),         # [0:8]
    ("RadioRoleEnum", "radioRole"),
    ("String", "radioType"),            # enum{"801.11[a|a/n|a/n/ac|b/g|b/g/n]"}
    ("smallint", "slotId"),             # [0:1]
    ("String", "txPowerControl")        # enum{Automatic, Custom}
).set_id_field("@id")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

add_table(archive, Table(
    "v2", "data", "WlanProfiles", True, DAY + offset, 1000,
    ("String", "@id"),
    ("String", "@displayName", False),  # dupl @id uncommented 2018-07-01
    ("boolean", "aaaAllowOverride"),    # allow AAA override?
    ("String", "aaaLdapPrimaryServer"),  # 1st LDAP server
    ("String", "aaaLdapSecondaryServer"),  # 2nd LDAP server
    ("String", "aaaLdapTertiaryServer"),  # 3rd LDAP server
    ("boolean", "aaaLocalEapAuthenticationEnabled"),  # local EAP auth?
    ("boolean", "aaaLocalEapAuthenticationProfileName"),  # if so, the profile
    ("String", "aaaRadiusAccountingPrimaryServer"),
    # The 1st, when aaaRadiusAccountingServersEnabled
    ("String", "aaaRadiusAccountingSecondaryServer"),
    # The 2nd, when aaaRadiusAccountingSeversEnabled
    ("boolean", "aaaRadiusAccountingServersEnabled"),  # RADIUS accounting?
    ("String", "aaaRadiusAccountingTertiaryServer"),
    # The 3rd, when aaaRadiusAccountingSeversEnabled
    ("String", "aaaRadiusAuthenticationPrimaryServer"),
    # The 1st, when aaaRadiusAuthorizationServersEnabled
    ("String", "aaaRadiusAuthenticationSecondaryServer"),
    # The 2nd, when aaaRadiusAuthorizationServersEnabled
    ("boolean", "aaaRadiusAuthenticationServersEnabled"),  # RADIUS authorization?
    ("String", "aaaLocalEapAuthenticationProfileName"),  # ... if so, the EAP profile to use
    ("String", "aaaRadiusAuthenticationTertiaryServer"),
    # The 3rd, when aaaRadiusAuthorizationServersEnabled
    ("boolean", "aaaRadiusInterimUpdateEnabled"),  # RADIUS server accounting interim update?
    ("long", "aaaRadiusInterimUpdateInterval"),  # ... if so, the update interval in seconds
    ("boolean", "adminStatus"),         # WLAN administratively enabled?
    ("boolean", "advancedAironetIeEnabled"),  # Aironet Info Elements enabled for this WLAN?
    ("boolean", "advancedClientExclusionEnabled"),  # auto client exclusion?
    ("long", "advancedClientExclusionTimeout"),  # ... if so, tieout in seconds or 0 for infinite
    ("boolean", "advancedCoverageHoleDetectionEnabled"),  # coverage hole detection?
    ("boolean", "advancedDhcpAddressAssignmentRequired"),
    # each client required to obtain IP address via DHCP?
    ("boolean", "advancedDhcpProfilingEnabled"),
    # should the controller collect DHCP attribtes of clients on this WLAN?
    ("String", "advancedDhcpServerIpAddress_address"),
    # if valid, an IPv4 DHCP server specified for this WLAN
    ("boolean", "advancedDiagnosticChannelEnabled"),  # diagnostic channel available for this WLAN?
    ("long", "advancedDot11anDtimPeriod"),  # Delivery Traffic Indication Map (DTIM) for 802.11a/n
    # measured in beacons, during which [broad|multi]cast frames are transmitted
    ("long", "advancedDot11bgnDtimPeriod"),  # DTIM interval for 802.11b/g/n
    ("boolean", "advancedFlexConnectCentralDhcpProcessingEnabled"),
    ("boolean", "advancedFlexConnectLearnClientIpEnabled"),
    ("boolean", "advancedFlexConnectLocalAuthEnabled"),
    ("boolean", "advancedFlexConnectLocalSwitchingEnabled"),
    ("boolean", "advancedFlexConnectNatPatEnabled"),
    ("boolean", "advancedFlexConnectOverrideDnsEnabled"),
    ("boolean", "advancedFlexConnectReapCentralAssociation"),
    ("boolean", "advancedFlexConnectVlanCentralSwitchingEnabled"),
    ("boolean", "advancedHttpProfilingEnabled"),
    ("boolean", "advancedIpv6Enabled"),
    ("boolean", "advancedKtsCacEnabled"),
    ("boolean", "advancedLoadBalancingBandSelectEnabled"),
    ("boolean", "advancedLoadBalancingEnabled"),
    ("long", "advancedMaximumClients"),
    ("String", "advancedMdnsProfileName"),
    ("boolean", "advancedMdnsSnoopingEnabled"),
    ("boolean", "advancedMediaSessionSnoopingEnabled"),
    ("DisabledEnabledRequiredEnum", "advancedMfpClientProtection"),
    ("boolean", "advancedMfpSignatureGenerationEnabled"),
    ("long", "advancedMfpVersion"),
    ("String", "advancedOverrideInterfaceAclName"),
    ("String", "advancedOverrideInterfaceIpv6AclName"),
    ("boolean", "advancedPassiveClientEnabled"),
    ("Peer2PeerBlockingEnum", "advancedPeerToPeerBlocking"),
    ("PmipMobilityTypeEnum", "advancedPmipMobilityType"),
    ("String", "advancedPmipProfile"),
    ("String", "advancedPmipRealm"),
    ("boolean", "advancedScanDeferPriority0"),
    ("boolean", "advancedScanDeferPriority1"),
    ("boolean", "advancedScanDeferPriority2"),
    ("boolean", "advancedScanDeferPriority3"),
    ("boolean", "advancedScanDeferPriority4"),
    ("boolean", "advancedScanDeferPriority5"),
    ("boolean", "advancedScanDeferPriority6"),
    ("boolean", "advancedScanDeferPriority7"),
    ("long", "advancedScanDeferTime"),
    ("long", "advancedSessionTimeout"),
    ("DisabledAllowedNotAllowedEnum", "advancedWifiDirectClientsPolicy"),
    ("boolean", "broadcastSsidEnabled"),
    ("long", "ckipKeyIndex"),
    ("boolean", "ckipKeyPermutationEnabled"),
    ("CkipEncryptionTypeEnum", "ckipKeySize"),
    ("boolean", "ckipMmhModeEnabled"),
    ("boolean", "ckipSecurityEnabled"),
    ("long", "controllerId"),
    ("boolean", "hotspot2Enable_hotSpot2Enabled"),
    ("long", "hotspot2Wan_downLinkSpeed"),
    ("long", "hotspot2Wan_upLinkSpeed"),
    ("String", "hotspot2Wan_wanLinkStatus"),
    ("String", "hotspot2Wan_wanSymLinkStatus"),
    ("String", "hotspotGeneral_heSsid_octets"),
    ("boolean", "hotspotGeneral_internetAccess"),
    ("String", "hotspotGeneral_ipv4AddressAvailType"),
    ("String", "hotspotGeneral_ipv6AddressAvailType"),
    ("String", "hotspotGeneral_networkAuthType"),
    ("String", "hotspotGeneral_networkType"),
    ("boolean", "hotspotGeneral_status"),
    ("boolean", "hotspotServiceAdvertisement_msapEnable"),
    ("long", "hotspotServiceAdvertisement_serverIndex"),
    # We don't have hotspots. Ignore the embedded array in relational model
    # hotspotOperatorConfigTemplate[]
    # hotspotPortConfigTemplate
    # hotspotGppConfigTemplate[]
    # hotspotDomainConnfigTemplat[]
    #
    # ("String", "instanceUuid"),
    ("String", "interfaceName"),
    ("InterfaceMappingTypeEnum", "interfaceType"),
    ("String", "ipAddress", False),     # appeared in 3.6
    ("boolean", "isWiredLan"),
    ("LanTypeEnum", "lanType"),
    ("boolean", "layer2FastTransitionEnabled"),
    ("boolean", "layer2FastTransitionOverDsEnabled"),
    ("long", "layer2FastTransitionReassociationTimeout"),
    ("boolean", "layer2MacFilteringEnabled"),
    ("boolean", "layer3GlobalWebAuthEnabled"),
    ("String", "layer3PreauthenticationAcl"),
    ("String", "layer3PreauthenticationIpv6Acl"),
    ("boolean", "layer3VpnPassthroughEnabled"),
    ("String", "layer3WebAuthFlexAcl"),
    ("WlanWebAuthTypeEnum", "layer3WebAuthType"),
    ("boolean", "layer3WebPolicyAuthenticationEnabled"),
    ("boolean", "layer3WebPolicyConditionalRedirectEnabled"),
    ("boolean", "layer3WebPolicyOnMacFailureEnabled"),
    ("boolean", "layer3WebPolicyPassthroughEnabled"),
    ("boolean", "multicastVlanEnabled"),
    ("String", "multicastVlanInterface"),
    ("String", "profileName"),
    ("PhoneSupport7920Enum", "qos7920Cac"),
    ("String", "qosAvcProfileName"),
    ("boolean", "qosNbarVisibilityEnabled"),
    ("String", "qosNetflowMonitor"),
    ("long", "qosPerSSidBurstRealTimeUpstreamRate"),
    ("long", "qosPerSsidAverageDownstreamRate"),
    ("long", "qosPerSsidAverageRealTimeDownstreamRate"),
    ("long", "qosPerSsidAverageRealTimeUpstreamRate"),
    ("long", "qosPerSsidAverageUpstreamRate"),
    ("long", "qosPerSsidBurstDownstreamRate"),
    ("long", "qosPerSsidBurstRealTimeDownstreamRate"),
    ("long", "qosPerSsidBurstUpstreamRate"),
    ("long", "qosPerUserAverageDownstreamRate"),
    ("long", "qosPerUserAverageRealTimeDownstreamRate"),
    ("long", "qosPerUserAverageRealTimeUpstreamRate"),
    ("long", "qosPerUserAverageUpstreamRate"),
    ("long", "qosPerUserBurstDownstreamRate"),
    ("long", "qosPerUserBurstRealTimeDownstreamRate"),
    ("long", "qosPerUserBurstRealTimeUpstreamRate"),
    ("long", "qosPerUserBurstUpstreamRate"),
    ("QosEnum", "qosProfile"),
    ("DisabledAllowedRequiredEnum", "qosWmmPolicy"),
    ("RadioPolicyEnum", "radioPolicy"),
    ("String", "ssid"),
    ("String", "vpnPassThroughGatewayAddress_address"),
    ("String", "webAuthExternalUrl"),
    ("String", "webAuthLoginFailurePage"),
    ("String", "wwebAuthLoginPage"),
    ("String", "webAuthLogoutPage"),
    ("boolean", "webPassthruEmailInputEnabled"),
    ("boolean", "wepAllowSharedKeyAuthentication"),
    ("long", "wepKeyIndex"),
    ("WepEncryptionTypeEnum", "wepKeySize"),
    ("boolean", "wepSecurityEnabled"),
    ("long", "wlanId"),
    ("boolean", "wpa2Enabled"),
    ("boolean", "wpa2EncryptionProtocolAes"),
    ("boolean", "wpa2EncryptionProtocolTkip"),
    ("boolean", "wpaAuthenticationKeyManagement8021x"),
    ("boolean", "wpaAuthenticationKeyManagementCckm"),
    ("boolean", "wpaAuthenticationKeyManagementFt8021x"),
    ("boolean", "wpaAuthenticationKeyManagementFtPsk"),
    ("boolean", "wpaAuthenticationKeyManagementPmf8021x"),
    ("boolean", "wpaAuthenticationKeyManagementPmfPsk"),
    ("boolean", "wpaAuthenticationKeyManagementPsk"),
    ("boolean", "wpaEnabled"),
    ("boolean", "wpaEncryptionProtocolAes"),
    ("boolean", "wpaEncryptionProtocolTkip"),
    ("PskFormatEnum", "wpaPresharedKey", False),  # appeared in 3.6
    ("String", "wpaPresharedKeyFormat", False),  # appeared in 3.6
    ("boolean", "wpaSecurityEnabled"),
    ("x8021EncryptionTypeEnum", "x8021KeySize"),
    ("boolean", "x8021SecurityEnabled")
).set_id_field("@id")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

offset += 5*60.0
add_table(archive, Table(
    "v1", "data", "WlanProfiles", True, DAY + offset, 1000,
    ("String", "@id"),
    ("String", "@displayName"),         # duplicates @id
    ("boolean", "aaaAllowOverride"),    # is allow AAA override enabled?
    ("String", "aaaLdapPrimaryServer"),  # 1st LDAP server
    ("String", "aaaLdapSecondaryServer"),  # 2nd LDAP server
    ("String", "aaaLdapTertiaryServer"),  # 3rd LDAP server
    ("boolean", "aaaLocalEapAuthenticationEnabled"),  # local EAP authentication?
    ("boolean", "aaaLocalEapAuthenticationProfileName"),  # if so, the profile
    ("String", "aaaRadiusAccountingPrimaryServer"),
    # The 1st, when aaaRadiusAccountingServersEnabled
    ("String", "aaaRadiusAccountingSecondaryServer"),
    # The 2nd, when aaaRadiusAccountingServersEnabled
    ("boolean", "aaaRadiusAccountingServersEnabled"),  # RADIUS accounting?
    ("String", "aaaRadiusAccountingTertiaryServer"),
    # The 3rd, when aaaRadiusAccountingServersEnabled
    ("String", "aaaRadiusAuthenticationPrimaryServer"),
    # The 1st, when aaaRadiusAuthorizationServersEnabled
    ("String", "aaaRadiusAuthenticationSecondaryServer"),
    # The 2nd, when aaaRadiusAuthorizationServersEnabled
    ("boolean", "aaaRadiusAuthenticationServersEnabled"),  # RADIUS authorization?
    ("String", "aaaLocalEapAuthenticationProfileName"),  # if so, the profile
    ("String", "aaaRadiusAuthenticationTertiaryServer"),
    # The tertiary, when aaaRadiusAuthorizationServersEnabled
    ("boolean", "aaaRadiusInterimUpdateEnabled"),  # RADIUS server accounting interim update?
    ("long", "aaaRadiusInterimUpdateInterval"),  # if so, the update interval in seconds
    ("boolean", "adminStatus"),         # WLAN administratively enabled?
    ("boolean", "advancedAironetIeEnabled"),  # Aironet Info Elements enabled for this WLAN?
    ("boolean", "advancedClientExclusionEnabled"),  # auto client exclusion?
    ("long", "advancedClientExclusionTimeout"),  # ... if so, timeout in seconds or 0 for infinite
    ("boolean", "advancedCoverageHoleDetectionEnabled"),  # coverage hole detection?
    ("boolean", "advancedDhcpAddressAssignmentRequired"),
    # each client required to obtain IP address via DHCP?
    ("boolean", "advancedDhcpProfilingEnabled"),
    # should the controller collect DHCP attribtes of clients on this WLAN?
    ("String", "advancedDhcpServerIpAddress_address"),
    # if valid, an IPv4 DHCP server specified for this WLAN
    ("boolean", "advancedDiagnosticChannelEnabled"),  # diagnostic channel available for this WLAN?
    ("long", "advancedDot11anDtimPeriod"),  # Delivery Traffic Indication Map (DTIM) for 802.11a/n
    # measured in beacons, during which [broad|multi]cast frames are transmitted
    ("long", "advancedDot11bgnDtimPeriod"),  # DTIM interval for 802.11b/g/n
    ("boolean", "advancedFlexConnectCentralDhcpProcessingEnabled"),
    ("boolean", "advancedFlexConnectLearnClientIpEnabled"),
    ("boolean", "advancedFlexConnectLocalAuthEnabled"),
    ("boolean", "advancedFlexConnectLocalSwitchingEnabled"),
    ("boolean", "advancedFlexConnectNatPatEnabled"),
    ("boolean", "advancedFlexConnectOverrideDnsEnabled"),
    ("boolean", "advancedFlexConnectReapCentralAssociation"),
    ("boolean", "advancedFlexConnectVlanCentralSwitchingEnabled"),
    ("boolean", "advancedHttpProfilingEnabled"),
    ("boolean", "advancedIpv6Enabled"),
    ("boolean", "advancedKtsCacEnabled"),
    ("boolean", "advancedLoadBalancingBandSelectEnabled"),
    ("boolean", "advancedLoadBalancingEnabled"),
    ("long", "advancedMaximumClients"),
    ("String", "advancedMdnsProfileName"),
    ("boolean", "advancedMdnsSnoopingEnabled"),
    ("boolean", "advancedMediaSessionSnoopingEnabled"),
    ("DisabledEnabledRequiredEnum", "advancedMfpClientProtection"),
    ("boolean", "advancedMfpSignatureGenerationEnabled"),
    ("long", "advancedMfpVersion"),
    ("String", "advancedOverrideInterfaceAclName"),
    ("String", "advancedOverrideInterfaceIpv6AclName"),
    ("boolean", "advancedPassiveClientEnabled"),
    ("Peer2PeerBlockingEnum", "advancedPeerToPeerBlocking"),
    ("PmipMobilityTypeEnum", "advancedPmipMobilityType"),
    ("String", "advancedPmipProfile"),
    ("String", "advancedPmipRealm"),
    ("boolean", "advancedScanDeferPriority0"),
    ("boolean", "advancedScanDeferPriority1"),
    ("boolean", "advancedScanDeferPriority2"),
    ("boolean", "advancedScanDeferPriority3"),
    ("boolean", "advancedScanDeferPriority4"),
    ("boolean", "advancedScanDeferPriority5"),
    ("boolean", "advancedScanDeferPriority6"),
    ("boolean", "advancedScanDeferPriority7"),
    ("long", "advancedScanDeferTime"),
    ("long", "advancedSessionTimeout"),
    ("DisabledAllowedNotAllowedEnum", "advancedWifiDirectClientsPolicy"),
    ("boolean", "broadcastSsidEnabled"),
    ("long", "ckipKeyIndex"),
    ("boolean", "ckipKeyPermutationEnabled"),
    ("CkipEncryptionTypeEnum", "ckipKeySize"),
    ("boolean", "ckipMmhModeEnabled"),
    ("boolean", "ckipSecurityEnabled"),
    ("long", "controllerId"),
    ("boolean", "hotspot2Enable_hotSpot2Enabled"),
    ("long", "hotspot2Wan_downLinkSpeed"),
    ("long", "hotspot2Wan_upLinkSpeed"),
    ("String", "hotspot2Wan_wanLinkStatus"),
    ("String", "hotspot2Wan_wanSymLinkStatus"),
    ("String", "hotspotGeneral_heSsid_octets"),
    ("boolean", "hotspotGeneral_internetAccess"),
    ("String", "hotspotGeneral_ipv4AddressAvailType"),
    ("String", "hotspotGeneral_ipv6AddressAvailType"),
    ("String", "hotspotGeneral_networkAuthType"),
    ("String", "hotspotGeneral_networkType"),
    ("boolean", "hotspotGeneral_status"),
    ("boolean", "hotspotServiceAdvertisement_msapEnable"),
    ("long", "hotspotServiceAdvertisement_serverIndex"),
    # We don't have hotspots. Ignore the embedded array in relational model
    # hotspotOperatorConfigTemplate[]
    # hotspotPortConfigTemplate
    # hotspotGppConfigTemplate[]
    # hotspotDomainConnfigTemplat[]
    #
    ("String", "instanceUuid"),
    ("String", "interfaceName"),
    ("InterfaceMappingTypeEnum", "interfaceType"),
    ("boolean", "isWiredLan"),
    ("LanTypeEnum", "lanType"),
    ("boolean", "layer2FastTransitionEnabled"),
    ("boolean", "layer2FastTransitionOverDsEnabled"),
    ("long", "layer2FastTransitionReassociationTimeout"),
    ("boolean", "layer2MacFilteringEnabled"),
    ("boolean", "layer3GlobalWebAuthEnabled"),
    ("String", "layer3PreauthenticationAcl"),
    ("String", "layer3PreauthenticationIpv6Acl"),
    ("boolean", "layer3VpnPassthroughEnabled"),
    ("String", "layer3WebAuthFlexAcl"),
    ("WlanWebAuthTypeEnum", "layer3WebAuthType"),
    ("boolean", "layer3WebPolicyAuthenticationEnabled"),
    ("boolean", "layer3WebPolicyConditionalRedirectEnabled"),
    ("boolean", "layer3WebPolicyOnMacFailureEnabled"),
    ("boolean", "layer3WebPolicyPassthroughEnabled"),
    ("boolean", "multicastVlanEnabled"),
    ("String", "multicastVlanInterface"),
    ("String", "profileName"),
    ("PhoneSupport7920Enum", "qos7920Cac"),
    ("String", "qosAvcProfileName"),
    ("boolean", "qosNbarVisibilityEnabled"),
    ("String", "qosNetflowMonitor"),
    ("long", "qosPerSSidBurstRealTimeUpstreamRate"),
    ("long", "qosPerSsidAverageDownstreamRate"),
    ("long", "qosPerSsidAverageRealTimeDownstreamRate"),
    ("long", "qosPerSsidAverageRealTimeUpstreamRate"),
    ("long", "qosPerSsidAverageUpstreamRate"),
    ("long", "qosPerSsidBurstDownstreamRate"),
    ("long", "qosPerSsidBurstRealTimeDownstreamRate"),
    ("long", "qosPerSsidBurstUpstreamRate"),
    ("long", "qosPerUserAverageDownstreamRate"),
    ("long", "qosPerUserAverageRealTimeDownstreamRate"),
    ("long", "qosPerUserAverageRealTimeUpstreamRate"),
    ("long", "qosPerUserAverageUpstreamRate"),
    ("long", "qosPerUserBurstDownstreamRate"),
    ("long", "qosPerUserBurstRealTimeDownstreamRate"),
    ("long", "qosPerUserBurstRealTimeUpstreamRate"),
    ("long", "qosPerUserBurstUpstreamRate"),
    ("QosEnum", "qosProfile"),
    ("DisabledAllowedRequiredEnum", "qosWmmPolicy"),
    ("RadioPolicyEnum", "radioPolicy"),
    ("String", "ssid"),
    ("String", "vpnPassThroughGatewayAddress_address"),
    ("String", "webAuthExternalUrl"),
    ("String", "webAuthLoginFailurePage"),
    ("String", "wwebAuthLoginPage"),
    ("String", "webAuthLogoutPage"),
    ("boolean", "webPassthruEmailInputEnabled"),
    ("boolean", "wepAllowSharedKeyAuthentication"),
    ("long", "wepKeyIndex"),
    ("WepEncryptionTypeEnum", "wepKeySize"),
    ("boolean", "wepSecurityEnabled"),
    ("long", "wlanId"),
    ("boolean", "wpa2Enabled"),
    ("boolean", "wpa2EncryptionProtocolAes"),
    ("boolean", "wpa2EncryptionProtocolTkip"),
    ("boolean", "wpaAuthenticationKeyManagement8021x"),
    ("boolean", "wpaAuthenticationKeyManagementCckm"),
    ("boolean", "wpaAuthenticationKeyManagementFt8021x"),
    ("boolean", "wpaAuthenticationKeyManagementFtPsk"),
    ("boolean", "wpaAuthenticationKeyManagementPmf8021x"),
    ("boolean", "wpaAuthenticationKeyManagementPmfPsk"),
    ("boolean", "wpaAuthenticationKeyManagementPsk"),
    ("boolean", "wpaEnabled"),
    ("boolean", "wpaEncryptionProtocolAes"),
    ("boolean", "wpaEncryptionProtocolTkip"),
    ("boolean", "wpaSecurityEnabled"),
    ("x8021EncryptionTypeEnum", "x8021KeySize"),
    ("boolean", "x8021SecurityEnabled")
).set_id_field("@id")
          .set_query_options({".full": "true", ".nocount": "true"})
          )

add_table(test, Table(
    "v1", "data", "people", True, DAY + offset, 1000,
    ('int', 'id'),
    ('String', 'first'),
    ('String', 'last'),
    ('String', 'notes')
).set_id_field('id')
          )

if __name__ == '__main__':              # test
    report_type_uses(1)                 # report each type not used in a field definition
    print(f"NUMHIST={NUMHIST}")
