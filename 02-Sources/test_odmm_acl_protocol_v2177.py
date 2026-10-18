import pytest
from odmm_acl_protocol_v2177 import parse_protocol_acl, compare_protocol_acl, ProtocolACLError

def test_nfsv4_order_matters():
    a=parse_protocol_acl('NFSv4','nfs4_getfacl',b'A::OWNER@:rwa\nD::EVERYONE@:w')
    b=parse_protocol_acl('NFSv4','nfs4_getfacl',b'D::EVERYONE@:w\nA::OWNER@:rwa')
    assert not compare_protocol_acl(a,b)['ordered_entries_equal']
    assert not a.cutover_authorized

def test_smb_canonical_order_matters():
    a=parse_protocol_acl('SMB','smb_adapter',b'DENY|S-1-5-21-1|WRITE|EXPLICIT\nALLOW|S-1-5-21-1|READ|INHERITED')
    b=parse_protocol_acl('SMB','smb_adapter',b'ALLOW|S-1-5-21-1|READ|INHERITED\nDENY|S-1-5-21-1|WRITE|EXPLICIT')
    assert not compare_protocol_acl(a,b)['ordered_entries_equal']
    assert not compare_protocol_acl(a,a)['effective_access_verified']

def test_invalid_input_fail_closed():
    for protocol, data in [('NFSv4',b'garbage'),('SMB',b'ALLOW|bob|READ|EXPLICIT'),('SMB',b'')]:
        with pytest.raises(ProtocolACLError): parse_protocol_acl(protocol,'collector',data)

def test_incompatible_provenance_fails():
    a=parse_protocol_acl('NFSv4','collectorA',b'A::OWNER@:r')
    b=parse_protocol_acl('NFSv4','collectorB',b'A::OWNER@:r')
    with pytest.raises(ProtocolACLError,match='PROVENANCE'): compare_protocol_acl(a,b)

def test_bounded_and_strict():
    with pytest.raises(ProtocolACLError): parse_protocol_acl('NFSv4','collector',b'A::OWNER@:r',max_bytes=4)
    with pytest.raises(ProtocolACLError): parse_protocol_acl('NFSv4','collector',b'A::OWNER@:r\n',max_entries=0)
    with pytest.raises(ProtocolACLError): parse_protocol_acl('SMB','collector',b'ALLOW|S-1-5-21|READ|EXPLICIT\x00')
