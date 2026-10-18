import pytest
from odmm_nas_identity_fidelity_v2136 import build_mapping,assess_fidelity
from odmm_nas_acl_identity_v2135 import normalize_access

def ident(name='AD\\alice',sid='S-1-5-21-100',uid=1000,gid=100):
    return {'domain':'AD','name':name,'sid':sid,'uid':uid,'gid':gid}
def pair(name='AD\\alice'):
    return {'source':ident(name),'target':ident(name,uid=2000)}
def snap(v, principal='AD\\alice',model='NTFS'):
    return normalize_access(vendor=v,endpoint_id='array',acl_model=model,identity_domain='AD',complete=True,entries=[dict(path='/data',principal=principal,effect='DENY',rights=['READ'],inherited=False,ordinal=0)])
def test_mapping_digest_stable():
    a=pair();b=pair('AD\\bob');assert build_mapping([a,b],complete=True).digest==build_mapping([b,a],complete=True).digest
@pytest.mark.parametrize('p',[[pair(),pair()],[{'source':ident(),'target':ident(uid=True)}],[{'source':ident(sid='bad'),'target':ident()}],[{'source':ident(uid=-1),'target':ident()}],[{'source':ident(sid=None,uid=None,gid=None),'target':ident()}]])
def test_reject_bad(p):
    with pytest.raises(ValueError):build_mapping(p,complete=True)
def test_incomplete():
    with pytest.raises(ValueError):build_mapping([pair()])
def test_blocked_even_identical():
    result=assess_fidelity(snap('netapp_ontap'),snap('pure_flashblade'),build_mapping([pair()],complete=True))
    assert result['status']=='BLOCKED' and result['cutover_authorized'] is False and not result['effective_access_verified']
def test_unmapped():
    result=assess_fidelity(snap('netapp_ontap','AD\\bob'),snap('dell_onefs','AD\\bob'),build_mapping([pair()],complete=True))
    assert 'UNMAPPED_ACL_PRINCIPALS' in result['blockers']
def test_translation():
    result=assess_fidelity(snap('netapp_ontap'),snap('dell_onefs',model='NFS4'),build_mapping([pair()],complete=True))
    assert 'ACL_MODEL_TRANSLATION_REQUIRED' in result['blockers']
def test_unattested_probes():
    result=assess_fidelity(snap('netapp_ontap'),snap('dell_onefs'),build_mapping([pair()],complete=True),access_probes={'READ':True})
    assert 'SUPPLIED_ACCESS_PROBES_UNATTESTED' in result['blockers']
def test_same_vendor():
    with pytest.raises(ValueError):assess_fidelity(snap('netapp_ontap'),snap('netapp_ontap'),build_mapping([pair()],complete=True))
