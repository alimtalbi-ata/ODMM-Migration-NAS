import pytest
from odmm_acl_protocol_v2177 import parse_protocol_acl, ProtocolACLError
from odmm_acl_identity_v2180 import IdentityMapping, validate_mappings, compare_smb_acl_identities

A='S-1-5-21-100'; B='S-1-5-21-200'; C='S-1-5-21-300'
def evidence(lines):
    return parse_protocol_acl('SMB','smbcacls','\n'.join(lines).encode())
def m(a=A,b=B,attested=True):
    return IdentityMapping(a,b,'AD',attested)
def test_equivalent_ordered_acl():
    src=evidence([f'DENY|{A}|WRITE|EXPLICIT',f'ALLOW|{A}|READ|INHERITED'])
    dst=evidence([f'DENY|{B}|WRITE|EXPLICIT',f'ALLOW|{B}|READ|INHERITED'])
    r=compare_smb_acl_identities(src,dst,[m()]); assert r['ordered_acl_equal'] and not r['nas_cutover_authorized'] and not r['effective_access_verified']
def test_detect_order_difference():
    src=evidence([f'DENY|{A}|WRITE|EXPLICIT',f'ALLOW|{A}|READ|EXPLICIT'])
    dst=evidence([f'ALLOW|{B}|READ|EXPLICIT',f'DENY|{B}|WRITE|EXPLICIT'])
    assert len(compare_smb_acl_identities(src,dst,[m()])['differences'])==2
def test_detect_inheritance_difference():
    src=evidence([f'ALLOW|{A}|READ|INHERITED']); dst=evidence([f'ALLOW|{B}|READ|EXPLICIT'])
    assert not compare_smb_acl_identities(src,dst,[m()])['ordered_acl_equal']
def test_missing_mapping_fails_comparison():
    r=compare_smb_acl_identities(evidence([f'ALLOW|{A}|READ|EXPLICIT']),evidence([f'ALLOW|{B}|READ|EXPLICIT']),[])
    assert r['missing_identity_mappings']==[A] and not r['ordered_acl_equal']
@pytest.mark.parametrize('mapping',[IdentityMapping(A,B,'AD',False),IdentityMapping(A,B,'UNKNOWN',True),IdentityMapping('bad',B,'AD',True)])
def test_reject_unattested_or_invalid(mapping):
    with pytest.raises(ProtocolACLError): validate_mappings([mapping])
def test_reject_collision():
    with pytest.raises(ProtocolACLError): validate_mappings([m(),m(C,B)])
def test_reject_incompatible_collector():
    s=evidence([f'ALLOW|{A}|READ|EXPLICIT'])
    t=parse_protocol_acl('SMB','other',f'ALLOW|{B}|READ|EXPLICIT'.encode())
    with pytest.raises(ProtocolACLError): compare_smb_acl_identities(s,t,[m()])
