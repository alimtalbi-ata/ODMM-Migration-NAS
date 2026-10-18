from odmm_netapp_access_v2082 import assess_access_evidence
from odmm_netapp_quality_v2081 import assess_pair
from test_odmm_netapp_v2081 import inventory

def row(principal='S-1-1',observed=True,**kwargs):
    return dict(principal=principal,protocol='SMB',path='/data',operation='read',expected=True,observed=observed,identity_source='SID',**kwargs)

def check(s=None,t=None,m=None,mirror=None):
    return assess_access_evidence([row()] if s is None else s,[row(principal='S-2-2')] if t is None else t,[{'kind':'SID','source':'S-1-1','target':'S-2-2'}] if m is None else m,snapmirror=mirror)

def test_matching_evidence_still_never_authorizes_cutover():
    r=check();assert r['blockers']==[] and r['cutover_authorized'] is False and r['status']=='BLOCKED'
def test_access_drift():
    r=check(t=[row(principal='S-2-2',observed=False)]);assert 'EFFECTIVE_ACCESS_DRIFT' in r['blockers'] and len(r['differences'])==1
def test_missing_identity():assert 'IDENTITY_MAPPING_MISSING' in check(m=[])['blockers']
def test_conflicting_identity():assert 'IDENTITY_MAPPING_CONFLICT' in check(m=[{'kind':'SID','source':'S-1-1','target':'S-2-2'},{'kind':'SID','source':'S-1-1','target':'S-3-3'}])['blockers']
def test_collision():assert 'IDENTITY_MAPPING_COLLISION' in check(m=[{'kind':'SID','source':'S-1-1','target':'S-2-2'},{'kind':'SID','source':'S-3-3','target':'S-2-2'}])['blockers']
def test_missing_target_proof():assert 'TARGET_ACCESS_PROOF_MISSING' in check(t=[])['blockers']
def test_invalid_sample():assert 'SOURCE_ACCESS_EVIDENCE_INCOMPLETE' in check(s=[{'principal':'x'}])['blockers']
def test_duplicate_sample():assert 'SOURCE_ACCESS_EVIDENCE_DUPLICATE' in check(s=[row(),row()])['blockers']
def test_source_expectation_mismatch():assert 'SOURCE_ACCESS_EXPECTATION_MISMATCH' in check(s=[row(observed=False)])['blockers']
def test_snapmirror_lag():assert 'SNAPMIRROR_RPO_NOT_MET_OR_UNVERIFIED' in check(mirror={'healthy':True,'lag_seconds':61,'rpo_seconds':60})['blockers']
def test_snapmirror_within_rpo():assert 'SNAPMIRROR_RPO_NOT_MET_OR_UNVERIFIED' not in check(mirror={'healthy':True,'lag_seconds':10,'rpo_seconds':60})['blockers']
def test_quality_integration():
    r=assess_pair(inventory(),inventory(),access_evidence={'source_tests':[row()],'target_tests':[row(principal='S-2-2',observed=False)],'identity_mappings':[{'kind':'SID','source':'S-1-1','target':'S-2-2'}]})
    assert 'EFFECTIVE_ACCESS_DRIFT' in r['blockers'] and r['cutover_authorized'] is False
