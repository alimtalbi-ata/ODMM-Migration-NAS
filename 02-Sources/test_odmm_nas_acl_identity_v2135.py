import pytest
from odmm_nas_acl_identity_v2135 import normalize_access,compare_access

def ace(ordinal=0,effect='DENY'):
    return dict(path='/data',principal='AD\\user',effect=effect,rights=['READ'],inherited=False,ordinal=ordinal)

def snap(v,entries=None,**kw):
    return normalize_access(vendor=v,endpoint_id='array1',acl_model='NTFS',identity_domain='AD',entries=[ace()] if entries is None else entries,complete=True,**kw)

def test_same():
    r=compare_access(snap('netapp_ontap'),snap('pure_flashblade'))
    assert r['status']=='BLOCKED' and r['cutover_authorized'] is False

def test_order_matters():
    a=snap('netapp_ontap',[ace(0,'DENY'),ace(1,'ALLOW')]);b=snap('dell_onefs',[ace(1,'DENY'),ace(0,'ALLOW')])
    assert 'ACE_ORDER_OR_CONTENT_MISMATCH' in compare_access(a,b)['blockers']

def test_acl_model_mismatch():
    a=snap('netapp_ontap');b=normalize_access(vendor='dell_onefs',endpoint_id='array1',acl_model='NFS4',identity_domain='AD',entries=[ace()],complete=True)
    assert 'ACL_MODEL_MISMATCH' in compare_access(a,b)['blockers']

@pytest.mark.parametrize('entries',[[ace(0),ace(0)],[dict(ace(),effect='OTHER')],[dict(ace(),rights=[])],[dict(ace(),path='/a/../b')]])
def test_invalid(entries):
    with pytest.raises(ValueError):snap('netapp_ontap',entries)

def test_incomplete():
    with pytest.raises(ValueError):normalize_access(vendor='netapp_ontap',endpoint_id='a',acl_model='NTFS',identity_domain='AD',entries=[],complete=False)

def test_identity_mismatch():
    a=snap('netapp_ontap');b=normalize_access(vendor='dell_onefs',endpoint_id='array1',acl_model='NTFS',identity_domain='LDAP',entries=[ace()],complete=True)
    assert 'IDENTITY_DOMAIN_MISMATCH' in compare_access(a,b)['blockers']

def test_deterministic():
    assert snap('netapp_ontap',[ace(1,'ALLOW'),ace(0)]).digest==snap('netapp_ontap',[ace(0),ace(1,'ALLOW')]).digest

def test_same_vendor_rejected():
    with pytest.raises(ValueError):compare_access(snap('netapp_ontap'),snap('netapp_ontap'))
