import subprocess
import pytest
from odmm_acl_smb_v2179 import collect_smb_remote, normalize_smbcacls
from odmm_acl_protocol_v2177 import ProtocolACLError

RAW=b'REVISION:1\nOWNER:S-1-5-21-100\nACL:S-1-5-21-100:ALLOWED/0x0/READ\nACL:S-1-5-21-101:DENIED/0x0/WRITE\n'
def test_normalize_order():
    assert normalize_smbcacls(RAW).splitlines()==[b'ALLOW|S-1-5-21-100|READ|EXPLICIT',b'DENY|S-1-5-21-101|WRITE|EXPLICIT']
def test_remote_read_only(monkeypatch):
    def fake(args,**kwargs):
        assert args==['/usr/bin/smbcacls','//nas/share','dir/file','-n']
        assert kwargs['timeout']==5 and kwargs['stdin']==subprocess.DEVNULL
        return subprocess.CompletedProcess(args,0,RAW,b'')
    monkeypatch.setattr(subprocess,'run',fake)
    x=collect_smb_remote('//nas/share','dir/file')
    assert len(x.evidence.entries)==2 and not x.cutover_authorized and not x.effective_access_verified
@pytest.mark.parametrize('raw',[b'ACL:DOMAIN\\user:ALLOWED/0x0/READ',b'ACL:S-1-5-21-100:ALLOWED/0x1/READ',b'ACL:S-1-5-21-100:ALLOWED/0x0/BOGUS',b'garbage',b''])
def test_reject_ambiguous(raw):
    with pytest.raises(ProtocolACLError): normalize_smbcacls(raw)
@pytest.mark.parametrize('share,path',[('//host/share','../etc'),('//host/share','/abs'),('//host/share','a//b'),('//bad host/share','file')])
def test_reject_paths(share,path):
    with pytest.raises(ProtocolACLError): collect_smb_remote(share,path)
def test_failure(monkeypatch):
    monkeypatch.setattr(subprocess,'run',lambda *a,**k: subprocess.CompletedProcess(a,1,b'',b'err'))
    with pytest.raises(ProtocolACLError): collect_smb_remote('//nas/share','file')
def test_credentials_permissions(tmp_path):
    p=tmp_path/'cred'; p.write_text('username=x'); p.chmod(0o644)
    with pytest.raises(ProtocolACLError): collect_smb_remote('//nas/share','file',credentials_file=p)
