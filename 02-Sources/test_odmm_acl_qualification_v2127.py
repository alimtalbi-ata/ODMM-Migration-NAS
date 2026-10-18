import pytest
from odmm_acl_qualification_v2127 import qualify_acl_pair, RIGHTS

def ep(vendor, **kw):
    e = dict(vendor=vendor, protocol='NFS4', acl_model='NFS4', identity_domain='AD',
             snapshot_complete=True, acl_entries=[dict(principal='AD\\alice', effect='DENY', rights=['DELETE'], inherited=False)])
    e.update(kw)
    return e

def probes(**kw):
    p = {r: False for r in RIGHTS}; p.update(kw)
    return {'AD\\alice': {'source': p, 'target': dict(p)}}

@pytest.mark.parametrize('a,b', [('netapp','flashblade'),('flashblade','netapp'),('onefs','netapp'),('netapp','onefs'),('onefs','flashblade'),('flashblade','onefs')])
def test_six_directions_always_blocked(a,b):
    x=qualify_acl_pair(ep(a),ep(b),identity_mapping={'AD\\alice':'AD\\alice'},effective_access=probes())
    assert x.status=='BLOCKED' and not x.cutover_authorized and not x.acl_fidelity_verified
    assert x.checked_principals==1

def test_deny_ace_cannot_disappear():
    x=qualify_acl_pair(ep('netapp'),ep('flashblade',acl_entries=[dict(principal='AD\\alice',effect='ALLOW',rights=['DELETE'],inherited=False)]))
    assert any('MISSING_TARGET_ACE' in v for v in x.discrepancies)

def test_effective_access_mismatch():
    p=probes();p['AD\\alice']['target']['DELETE']=True
    x=qualify_acl_pair(ep('netapp'),ep('flashblade'),effective_access=p,identity_mapping={'AD\\alice':'AD\\alice'})
    assert any('EFFECTIVE_ACCESS_MISMATCH' in v for v in x.discrepancies)

def test_incomplete_snapshot():
    x=qualify_acl_pair(ep('netapp',snapshot_complete=False),ep('onefs'))
    assert 'SOURCE_SNAPSHOT_INCOMPLETE' in x.blockers

def test_bad_acl():
    x=qualify_acl_pair(ep('netapp',acl_entries=[dict(principal='x',effect='ALLOW',rights=['SUPERUSER'],inherited=False)]),ep('onefs'))
    assert 'SOURCE_ACL_ENTRY_INVALID' in x.blockers

def test_identity_collision():
    x=qualify_acl_pair(ep('netapp'),ep('onefs'),identity_mapping={'a':'same','b':'same'})
    assert 'IDENTITY_MAPPING_COLLISION' in x.blockers

def test_missing_probe():
    x=qualify_acl_pair(ep('netapp'),ep('onefs'),effective_access={})
    assert 'EFFECTIVE_ACCESS_EVIDENCE_MISSING' in x.blockers

def test_cross_protocol():
    x=qualify_acl_pair(ep('netapp'),ep('onefs',protocol='SMB3'))
    assert 'CROSS_PROTOCOL_TRANSLATION_UNQUALIFIED' in x.blockers

def test_invalid_endpoints():
    with pytest.raises(ValueError): qualify_acl_pair(None,{})
