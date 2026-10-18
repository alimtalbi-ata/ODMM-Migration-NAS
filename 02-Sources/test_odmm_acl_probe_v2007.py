import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from odmm_acl_probe_v2007 import probe,compare,ACLProbeError

class ACLProbeTests(unittest.TestCase):
 def test_collect(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,'file').write_text('a')
   with patch('odmm_acl_probe_v2007.shutil.which',return_value='/usr/bin/getfacl'):
    out=probe(d,'file',runner=lambda *a,**k:SimpleNamespace(returncode=0,stdout='# file: x\nuser::rw-\ngroup::r--\nother::---\n'))
   self.assertEqual(out['status'],'POSIX_ACL_COLLECTED');self.assertFalse(out['cutover_authorized'])
 def test_missing_tool(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,'f').touch()
   with patch('odmm_acl_probe_v2007.shutil.which',return_value=None): self.assertEqual(probe(d,'f')['status'],'NOT_COLLECTED')
 def test_traversal(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ACLProbeError): probe(d,'../escape')
 def test_symlink(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,'link').symlink_to('/etc/passwd')
   with self.assertRaises(ACLProbeError): probe(d,'link')
 def test_mismatch(self):
  self.assertEqual(compare({'status':'POSIX_ACL_COLLECTED','entries':['a']},{'status':'POSIX_ACL_COLLECTED','entries':['b']})['status'],'BLOCKED')
 def test_match_not_qualified(self):
  result=compare({'status':'POSIX_ACL_COLLECTED','entries':['a']},{'status':'POSIX_ACL_COLLECTED','entries':['a']})
  self.assertFalse(result['cutover_authorized'])
 def test_failure(self):
  with tempfile.TemporaryDirectory() as d:
   Path(d,'f').touch()
   with patch('odmm_acl_probe_v2007.shutil.which',return_value='/usr/bin/getfacl'):
    with self.assertRaises(ACLProbeError): probe(d,'f',runner=lambda *a,**k:SimpleNamespace(returncode=1,stdout=''))
if __name__=='__main__': unittest.main()
