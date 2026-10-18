import pytest
from odmm_nas_identity_preflight_v2175 import preflight
from odmm_nas_six_direction_gate_v2174 import REQUIRED, TRIAD
from native_tree_migration import NativeTreeMigration, MigrationBlocked

def endpoints(s,t):
    return ({'vendor':s,'protocol':'SMB3','namespace':'/src','inventory_complete':True},
            {'vendor':t,'protocol':'SMB3','namespace':'/dst','inventory_complete':True})

def test_six_directions_are_blocked_even_with_complete_proofs():
    for s in TRIAD:
        for t in TRIAD:
            if s == t: continue
            r=preflight(*endpoints(s,t), identities=[{'kind':'SID','source':'S-1-5-21-1','target':'S-1-5-21-2'}],
                acl_samples=[{'path':'/share/f','source_acl':'allow','target_acl':'allow','effective_access_verified':True,'acl_equivalent':True}],
                evidence={k:True for k in REQUIRED})
            assert r.blockers == ('VENDOR_NAS_NOT_PHYSICALLY_QUALIFIED',)
            assert not r.cutover_authorized and not r.acl_fidelity_verified

def test_collision_and_missing_effective_rights():
    r=preflight(*endpoints('netapp','flashblade'), identities=[{'kind':'UID','source':'100','target':'200'}, {'kind':'UID','source':'101','target':'200'}],
        acl_samples=[{'path':'/f','source_acl':'a','target_acl':'b','effective_access_verified':'yes','acl_equivalent':False}])
    assert 'IDENTITY_MAPPING_COLLISION' in r.blockers
    assert 'EFFECTIVE_ACCESS_UNVERIFIED' in r.blockers
    assert 'ACL_EQUIVALENCE_UNVERIFIED' in r.blockers

def test_missing_and_invalid_rows():
    r=preflight(*endpoints('onefs','netapp'),identities=[{'kind':'UID','source':1,'target':'2'}],acl_samples=[{'path':'relative'}])
    assert 'IDENTITY_ROW_INVALID' in r.blockers and 'ACL_SAMPLE_INVALID' in r.blockers

def test_tree_refuses_vendor_preflight_before_copy(tmp_path):
    src=tmp_path/'src'; dst=tmp_path/'dst'; src.mkdir(); dst.mkdir(); (src/'a').write_text('data')
    report=preflight(*endpoints('netapp','onefs'), identities=[], acl_samples=[])
    with NativeTreeMigration(src,dst,tmp_path/'journal.sqlite') as engine:
        with pytest.raises(MigrationBlocked,match='NAS_PREFLIGHT_NOT_QUALIFIED'):
            engine.run(nas_preflight=report)
    assert not (dst/'a').exists()
