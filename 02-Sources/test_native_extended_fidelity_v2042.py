import os, tempfile, unittest
from pathlib import Path
from native_extended_fidelity_v2042 import compare_trees
class FidelityTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
  self.a=Path(self.t.name)/'a'; self.b=Path(self.t.name)/'b'; self.a.mkdir();self.b.mkdir()
  (self.a/'f').write_bytes(b'hello');(self.b/'f').write_bytes(b'hello')
  st=(self.a/'f').stat();os.utime(self.b/'f',ns=(st.st_atime_ns,st.st_mtime_ns))
 def run_compare(self,**kw):return compare_trees(self.a,self.b,**kw)
 def test_match(self):self.assertEqual(self.run_compare(required=('content',))['status'],'MATCH')
 def test_content(self):
  (self.b/'f').write_bytes(b'other');self.assertEqual(self.run_compare(required=('content',))['status'],'MISMATCH')
 def test_missing(self):
  (self.b/'f').unlink();self.assertEqual(self.run_compare()['status'],'MISMATCH')
 def test_acl_fail_closed(self):self.assertEqual(self.run_compare(required=('nfs4_acl',))['status'],'UNVERIFIED')
 def test_ads_fail_closed(self):self.assertEqual(self.run_compare(required=('smb_ads',))['status'],'UNVERIFIED')
 def test_hardlink(self):
  os.link(self.a/'f',self.a/'g');(self.b/'g').write_bytes(b'hello');self.assertEqual(self.run_compare(required=('hardlinks',))['status'],'MISMATCH')
 def test_symlink(self):
  (self.a/'link').symlink_to('f');(self.b/'link').symlink_to('missing');self.assertEqual(self.run_compare(required=('content',))['status'],'MISMATCH')
 def test_unknown_requirement(self):
  with self.assertRaises(ValueError):self.run_compare(required=('fake',))
 def test_limit(self):
  with self.assertRaises(ValueError):self.run_compare(max_entries=0)
 def test_safety(self):
  r=self.run_compare(required=('content',));self.assertFalse(r['cutover_authorized']);self.assertFalse(r['writes_to_nas'])
if __name__=='__main__':unittest.main()
