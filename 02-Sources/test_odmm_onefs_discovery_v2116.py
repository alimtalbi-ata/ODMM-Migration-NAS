import pytest
from odmm_onefs_discovery_v2116 import discover_onefs, compare_onefs_ontap

def fetch(route):
    return {'/platform/16/zones':{'zones':[{'name':'zoneA'}]},
            '/platform/16/protocols/nfs/exports':{'exports':[{'paths':['/ifs/data']}]},
            '/platform/16/protocols/smb/shares':{'shares':[]}}[route]

def test_nfs_discovery():
    x=discover_onefs(fetch,access_zone='zoneA',path='/ifs/data')
    assert x.endpoint['discovered_protocols']==('NFS',)
    assert not x.blockers

def test_both_directions_blocked():
    x=discover_onefs(fetch,access_zone='zoneA',path='/ifs/data')
    for d in ('ONEFS_TO_NETAPP','NETAPP_TO_ONEFS'):
        r=compare_onefs_ontap({'namespace_id':'svm/vol'},x,direction=d)
        assert r['status']=='BLOCKED' and not r['cutover_authorized']
        assert r['engine']=='ODMM_NATIVE'

def test_missing_zone_blocks():
    x=discover_onefs(fetch,access_zone='other',path='/ifs/data')
    assert 'ONEFS_ACCESS_ZONE_UNVERIFIED' in x.blockers

def test_outage_fail_closed():
    def bad(_): raise ConnectionError()
    x=discover_onefs(bad,access_zone='zoneA',path='/ifs/data')
    assert len(x.blockers)>=3

def test_unqualified_version_rejected():
    with pytest.raises(ValueError): discover_onefs(fetch,access_zone='zoneA',path='/ifs/data',api_version='v15')

@pytest.mark.parametrize('path',['/etc/passwd','/ifs/../etc','/ifs/data?foo','/ifs/\x00'])
def test_invalid_path(path):
    with pytest.raises(ValueError): discover_onefs(fetch,access_zone='zoneA',path=path)

def test_wrong_direction():
    x=discover_onefs(fetch,access_zone='zoneA',path='/ifs/data')
    with pytest.raises(ValueError): compare_onefs_ontap({},x,direction='ONEFS_TO_FLASHBLADE')

def test_ambiguous_smb_blocks():
    def mixed(route):
        if route.endswith('/shares'): return {'shares':[{'zone':'zoneA','path':'/ifs/other'}]}
        return fetch(route)
    x=discover_onefs(mixed,access_zone='zoneA',path='/ifs/data')
    assert 'ONEFS_SMB_NAMESPACE_AMBIGUOUS' in x.blockers
