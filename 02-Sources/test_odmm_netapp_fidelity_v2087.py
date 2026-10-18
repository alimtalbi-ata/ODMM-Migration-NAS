from odmm_netapp_fidelity_v2087 import assess_fidelity,stamp_evidence
from odmm_netapp_cockpit_v2085 import assess_differences,render_differences

def rec(owner='S-1',acl=None,**kwargs):
    r=dict(path='/data',owner=owner,group=owner,acl_kind='NTFS',acl=[{'type':'DENY','principal':'Everyone','mask':'write'}] if acl is None else acl,xattrs={},ads={},inheritance=True,evidence_id='proof-001')
    r.update(kwargs);return stamp_evidence(r)

def maps():return [{'kind':'SID','source':'S-1','target':'T-1'}]

def test_identical_mapped_proofs():
    r=assess_fidelity([rec()],[rec(owner='T-1')],maps());assert r['blockers']==[] and r['proofs_compared']==1 and r['cutover_authorized'] is False

def test_acl_order_is_significant():
    acl=[{'type':'ALLOW','principal':'Everyone','mask':'read'},{'type':'DENY','principal':'Everyone','mask':'write'}]
    r=assess_fidelity([rec(acl=acl)],[rec(owner='T-1',acl=list(reversed(acl)))],maps());assert 'FIDELITY_ACL_DRIFT' in r['blockers']

def test_metadata_and_inheritance_drift():
    r=assess_fidelity([rec()],[rec(owner='T-1',xattrs={'a':'b'},ads={'stream':'abc'},inheritance=False)],maps())
    assert {'FIDELITY_XATTRS_DRIFT','FIDELITY_ADS_DRIFT','FIDELITY_INHERITANCE_DRIFT'}<=set(r['blockers'])

def test_missing_target_and_tampered_hash():
    assert 'TARGET_FIDELITY_PROOFS_MISSING' in assess_fidelity([rec()],[],maps())['blockers']
    bad=rec();bad['owner']='TAMPER';assert 'SOURCE_FIDELITY_HASH_INVALID' in assess_fidelity([bad],[rec(owner='T-1')],maps())['blockers']

def test_identity_collision():
    m=maps()+[{'kind':'SID','source':'S-2','target':'T-1'}]
    assert 'IDENTITY_MAPPING_COLLISION' in assess_fidelity([rec()],[rec(owner='T-1')],m)['blockers']

def test_cockpit_includes_fidelity_drift_and_escaped_html():
    args=dict(source_policy={'complete':True,'rules':[]},target_policy={'complete':True,'rules':[]},source_tests=[{'principal':'S-1','protocol':'SMB','path':'/data','operation':'read','expected':True,'observed':True,'identity_source':'SID'}],target_tests=[{'principal':'T-1','protocol':'SMB','path':'/data','operation':'read','expected':True,'observed':True,'identity_source':'SID'}],identity_mappings=maps(),source_fidelity=[rec()],target_fidelity=[rec(owner='T-1',xattrs={'<script>':'x'})])
    result=assess_differences(**args);assert 'FIDELITY_XATTRS_DRIFT' in result['blockers'] and result['fidelity_proofs_compared']==1
    assert '<script>' not in render_differences(result)

def test_empty_proofs_blocked():
    assert 'SOURCE_FIDELITY_PROOFS_MISSING' in assess_fidelity([],[],maps())['blockers']
