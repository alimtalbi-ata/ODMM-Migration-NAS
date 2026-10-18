import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from odmm_protocol_acl_probe_v2008 import probe_nfsv4,probe_smb,compare_protocol_evidence,ProtocolACLProbeError
class TestProtocolACL(unittest.TestCase):
 def test_nfsv4(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,'f').write_text('x')
   with patch('odmm_protocol_acl_probe_v2008.shutil.which',return_value='/usr/bin/nfs4_getfacl'):
    result=probe_nfsv4(d,'f',runner=lambda cmd,**kw:SimpleNamespace(returncode=0,stdout='A::OWNER@:rwatTnNcCy\n'))
   self.assertEqual(result['protocol'],'NFSV4');self.assertFalse(result['cutover_authorized'])
 def test_smb_kerberos_only(self):
  commands=[]
  def runner(cmd,**kw):commands.append(cmd);return SimpleNamespace(returncode=0,stdout='ACL:DOMAIN\\user:ALLOWED/0x0/READ\n')
  with patch('odmm_protocol_acl_probe_v2008.shutil.which',return_value='/usr/bin/smbcacls'):
   result=probe_smb('nas.example','share','folder/file',runner=runner)
  self.assertEqual(result['protocol'],'SMB');self.assertIn('--use-kerberos=required',commands[0]);self.assertIn('--no-pass',commands[0])
 def test_invalid_smb_endpoint(self):
  with self.assertRaises(ProtocolACLProbeError):probe_smb('nas;bad','share','a')
 def test_traversal(self):
  with self.assertRaises(ProtocolACLProbeError):probe_smb('nas','share','../secret')
 def test_symlink(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,'link').symlink_to('/etc/passwd')
   with self.assertRaises(ProtocolACLProbeError):probe_nfsv4(d,'link')
 def test_missing_tool(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,'f').touch()
   with patch('odmm_protocol_acl_probe_v2008.shutil.which',return_value=None):self.assertEqual(probe_nfsv4(d,'f')['status'],'NOT_COLLECTED')
 def test_cross_protocol_blocked(self):
  a={'status':'COLLECTED_UNVERIFIED','protocol':'NFSV4','entries':['a']}
  b={'status':'COLLECTED_UNVERIFIED','protocol':'SMB','entries':['a']}
  self.assertEqual(compare_protocol_evidence(a,b)['status'],'BLOCKED')
 def test_equal_not_qualified(self):
  a={'status':'COLLECTED_UNVERIFIED','protocol':'NFSV4','entries':['a']}
  self.assertFalse(compare_protocol_evidence(a,a)['cutover_authorized'])
 def test_empty_output(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,'f').touch()
   with patch('odmm_protocol_acl_probe_v2008.shutil.which',return_value='/usr/bin/nfs4_getfacl'):
    with self.assertRaises(ProtocolACLProbeError):probe_nfsv4(d,'f',runner=lambda *a,**kw:SimpleNamespace(returncode=0,stdout=''))
if __name__=='__main__':unittest.main()
