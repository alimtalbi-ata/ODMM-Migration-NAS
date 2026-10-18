import copy
import pytest
from odmm_nas_acl_semantics_v2146 import normalize_acl,compare_acl_semantics

def sample(vendor='netapp_ontap',protocol='NFS4',effect='ALLOW'):
    return normalize_acl(vendor=vendor,protocol=protocol,share='/data',domain='corp',identity_map={'uid:100':'user:a'},aces=[{'ordinal':0,'principal':'uid:100','effect':effect,'rights':['READ'],'inherited':False,'inheritance_flags':[]}],complete=True)

@pytest.mark.parametrize('a,b',[('netapp_ontap','pure_flashblade'),('pure_flashblade','netapp_ontap'),('netapp_ontap','dell_onefs'),('dell_onefs','netapp_ontap'),('pure_flashblade','dell_onefs'),('dell_onefs','pure_flashblade')])
def test_directions(a,b):
    result=compare_acl_semantics(sample(a),sample(b));assert result['issues']==[] and result['status']=='BLOCKED' and not result['cutover_authorized']

def test_deny_difference():
    assert 'ACE_ORDER_OR_SEMANTICS_MISMATCH' in compare_acl_semantics(sample(),sample('pure_flashblade',effect='DENY'))['issues']

def test_tamper():
    a=sample();a['aces'][0]=(0,'user:a','DENY',('READ',),False,())
    with pytest.raises(ValueError,match='TAMPERED'):compare_acl_semantics(a,sample('pure_flashblade'))

def test_missing_identity():
    with pytest.raises(ValueError,match='INVALID_ACE'):
        normalize_acl(vendor='netapp_ontap',protocol='NFS4',share='/data',domain='corp',identity_map={},aces=[{'ordinal':0,'principal':'uid:100','effect':'ALLOW','rights':['READ'],'inherited':False,'inheritance_flags':[]}],complete=True)

def test_identity_collision():
    with pytest.raises(ValueError,match='COLLISION'):
        normalize_acl(vendor='netapp_ontap',protocol='SMB3',share='/data',domain='corp',identity_map={'sid:a':'user:a','sid:b':'user:a'},aces=[],complete=True)

def test_no_incomplete():
    with pytest.raises(ValueError):normalize_acl(vendor='dell_onefs',protocol='NFS4',share='/data',domain='corp',identity_map={},aces=[],complete=False)

def test_order_matters():
    def build(v,reverse):
        aces=[{'ordinal':i,'principal':'uid:100','effect':effect,'rights':['READ'],'inherited':False,'inheritance_flags':[]} for i,effect in enumerate(('DENY','ALLOW') if reverse else ('ALLOW','DENY'))]
        return normalize_acl(vendor=v,protocol='NFS4',share='/data',domain='corp',identity_map={'uid:100':'user:a'},aces=aces,complete=True)
    assert compare_acl_semantics(build('netapp_ontap',False),build('pure_flashblade',True))['issues']

def test_protocol_mismatch():
    with pytest.raises(ValueError):compare_acl_semantics(sample(),sample('pure_flashblade','SMB3'))
