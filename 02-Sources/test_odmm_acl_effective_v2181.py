import pytest
from odmm_acl_protocol_v2177 import parse_protocol_acl, ProtocolACLError
from odmm_acl_identity_v2180 import IdentityMapping
from odmm_acl_effective_v2181 import PrincipalEvidence, project_rights, compare_principal_rights
A='S-1-5-21-100'; B='S-1-5-21-200'; GA='S-1-5-21-101'; GB='S-1-5-21-201'
def acl(*rows): return parse_protocol_acl('SMB','smbcacls','\n'.join(rows).encode())
def p(u,g,attested=True): return PrincipalEvidence(u,(g,),'AD',attested)
def mappings(): return [IdentityMapping(A,B,'AD',True),IdentityMapping(GA,GB,'AD',True)]
def test_matching_projection():
    a=acl(f'DENY|{GA}|WRITE|EXPLICIT',f'ALLOW|{A}|READ,WRITE|EXPLICIT')
    b=acl(f'DENY|{GB}|WRITE|EXPLICIT',f'ALLOW|{B}|READ,WRITE|EXPLICIT')
    result=compare_principal_rights(a,b,p(A,GA),p(B,GB),mappings())
    assert result['offline_projection_equal'] and result['source_rights']['READ'] and not result['source_rights']['WRITE']
    assert not result['effective_access_verified'] and not result['nas_cutover_authorized']
def test_order_matters():
    a=acl(f'DENY|{GA}|WRITE|EXPLICIT',f'ALLOW|{A}|WRITE|EXPLICIT')
    b=acl(f'ALLOW|{B}|WRITE|EXPLICIT',f'DENY|{GB}|WRITE|EXPLICIT')
    assert compare_principal_rights(a,b,p(A,GA),p(B,GB),mappings())['differences']==['WRITE']
def test_unmapped_group_rejected():
    with pytest.raises(ProtocolACLError,match='MEMBERSHIP_MAPPING_MISMATCH'):
        compare_principal_rights(acl(f'ALLOW|{A}|READ|EXPLICIT'),acl(f'ALLOW|{B}|READ|EXPLICIT'),p(A,GA),p(B,GB),mappings()[:1])
def test_unattested_group_rejected():
    with pytest.raises(ProtocolACLError,match='UNATTESTED_MEMBERSHIP'):
        project_rights(acl(f'ALLOW|{A}|READ|EXPLICIT'),p(A,GA,False))
@pytest.mark.parametrize('rights',['FULL','READ,FULL','READ,READ'])
def test_unknown_or_duplicate_rights_rejected(rights):
    with pytest.raises(ProtocolACLError,match='UNSUPPORTED_RIGHTS'):
        project_rights(acl(f'ALLOW|{A}|{rights}|EXPLICIT'),p(A,GA))
def test_incompatible_provenance_rejected():
    a=acl(f'ALLOW|{A}|READ|EXPLICIT')
    b=parse_protocol_acl('SMB','other',f'ALLOW|{B}|READ|EXPLICIT'.encode())
    with pytest.raises(ProtocolACLError,match='INCOMPARABLE_PROVENANCE'):
        compare_principal_rights(a,b,p(A,GA),p(B,GB),mappings())
