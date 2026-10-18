import os
import subprocess
import pytest
from odmm_acl_collect_v2178 import collect_canonical_file, collect_nfsv4_local
from odmm_acl_protocol_v2177 import ProtocolACLError

def test_smb_file_import(tmp_path):
    p=tmp_path/'smb.acl'; p.write_bytes(b'DENY|S-1-5-21-1|WRITE|EXPLICIT\nALLOW|S-1-5-21-1|READ|INHERITED')
    r=collect_canonical_file('SMB',p)
    assert len(r.evidence.entries)==2 and not r.cutover_authorized and not r.effective_access_verified

def test_nfsv4_file_import(tmp_path):
    p=tmp_path/'nfs.acl'; p.write_bytes(b'A::OWNER@:r')
    assert collect_canonical_file('NFSv4',p).evidence.entries==('A::OWNER@:r',)

def test_symlink_rejected(tmp_path):
    p=tmp_path/'acl'; p.write_bytes(b'A::OWNER@:r'); link=tmp_path/'link'; link.symlink_to(p)
    with pytest.raises(OSError): collect_canonical_file('NFSv4',link)

def test_oversize_rejected(tmp_path):
    p=tmp_path/'acl'; p.write_bytes(b'x'*262145)
    with pytest.raises(ProtocolACLError): collect_canonical_file('SMB',p)

def test_live_collector_bounded_and_fail_closed(tmp_path,monkeypatch):
    p=tmp_path/'mount'; p.mkdir()
    def fake(args,**kw):
        assert args==['/usr/bin/nfs4_getfacl','--',str(p)]
        assert kw['timeout']==5 and kw['stdin']==subprocess.DEVNULL
        return subprocess.CompletedProcess(args,0,b'# file: mount\nA::OWNER@:r\n',b'')
    monkeypatch.setattr(subprocess,'run',fake)
    result=collect_nfsv4_local(p)
    assert result.evidence.entries==('A::OWNER@:r',) and not result.cutover_authorized
    with pytest.raises(ProtocolACLError): collect_nfsv4_local(p,executable='/bin/sh')

def test_live_failure(tmp_path,monkeypatch):
    p=tmp_path/'mount'; p.mkdir()
    monkeypatch.setattr(subprocess,'run',lambda *a,**k: subprocess.CompletedProcess(a,1,b'',b'error'))
    with pytest.raises(ProtocolACLError): collect_nfsv4_local(p)
