import tempfile,unittest,os
from pathlib import Path
from odmm_file_fidelity_v2024 import compare,verify
class Tests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
  self.a=Path(self.t.name)/'a';self.b=Path(self.t.name)/'b';self.a.mkdir();self.b.mkdir()
 def test_empty(self):
  r=compare(self.a,self.b);self.assertTrue(verify(r));self.assertEqual(r['status'],'UNVERIFIED');self.assertFalse(r['cutover_authorized'])
 def test_equal(self):
  (self.a/'x').write_bytes(b'abc');(self.b/'x').write_bytes(b'abc');os.utime(self.b/'x',ns=( (self.a/'x').stat().st_atime_ns,(self.a/'x').stat().st_mtime_ns ));r=compare(self.a,self.b);self.assertEqual(r['counts']['MISMATCH'],0)
 def test_content_mismatch(self):
  (self.a/'x').write_bytes(b'abc');(self.b/'x').write_bytes(b'abd');self.assertEqual(compare(self.a,self.b)['status'],'MISMATCH')
 def test_missing(self):
  (self.a/'x').write_bytes(b'abc');self.assertEqual(compare(self.a,self.b)['status'],'MISMATCH')
 def test_symlink(self):
  (self.a/'x').symlink_to('/etc/passwd');(self.b/'x').symlink_to('/etc/passwd');self.assertNotEqual(compare(self.a,self.b)['status'],'MATCH')
 def test_symlink_target_mismatch(self):
  (self.a/'x').symlink_to('a');(self.b/'x').symlink_to('b');self.assertEqual(compare(self.a,self.b)['status'],'MISMATCH')
 def test_hardlinks(self):
  (self.a/'x').write_bytes(b'abc');(self.a/'y').hardlink_to(self.a/'x');(self.b/'x').write_bytes(b'abc');(self.b/'y').write_bytes(b'abc');self.assertIn('hardlink_topology',[x['field'] for x in compare(self.a,self.b)['findings']])
 def test_overlap(self):
  with self.assertRaises(ValueError):compare(self.a,self.a)
 def test_root_symlink(self):
  p=Path(self.t.name)/'link';p.symlink_to(self.a,target_is_directory=True)
  with self.assertRaises(ValueError):compare(p,self.b)
 def test_limit(self):
  (self.a/'x').write_bytes(b'abc');(self.b/'x').write_bytes(b'abc')
  with self.assertRaises(ValueError):compare(self.a,self.b,max_file_bytes=2)
 def test_tamper(self):
  r=compare(self.a,self.b);r['status']='MATCH';self.assertFalse(verify(r))
 def test_invalid_limit(self):
  with self.assertRaises(ValueError):compare(self.a,self.b,max_entries=True)
if __name__=='__main__':unittest.main()
