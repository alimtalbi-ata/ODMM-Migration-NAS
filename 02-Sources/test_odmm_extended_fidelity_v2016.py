import tempfile,unittest,os
from pathlib import Path
from odmm_extended_fidelity_v2016 import inventory,compare,verify
class Extended(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.a=Path(self.tmp.name)/'a';self.b=Path(self.tmp.name)/'b';self.a.mkdir();self.b.mkdir()
 def test_empty(self):
  r=compare(self.a,self.b);self.assertTrue(verify(r));self.assertFalse(r['cutover_authorized'])
 def test_missing(self):
  (self.a/'file').write_text('a');self.assertEqual(compare(self.a,self.b)['status'],'MISMATCH')
 def test_xattr(self):
  (self.a/'file').write_text('a');(self.b/'file').write_text('a')
  try:os.setxattr(self.a/'file','user.odmm',b'a');os.setxattr(self.b/'file','user.odmm',b'b')
  except OSError:self.skipTest('xattrs unavailable')
  self.assertIn('xattrs',[x['field'] for x in compare(self.a,self.b)['differences']])
 def test_symlink(self):
  (self.a/'l').symlink_to('x');(self.b/'l').symlink_to('y')
  self.assertIn('link_target',[x['field'] for x in compare(self.a,self.b)['differences']])
 def test_hardlinks(self):
  (self.a/'a').write_text('a');os.link(self.a/'a',self.a/'b')
  (self.b/'a').write_text('a');(self.b/'b').write_text('a')
  self.assertIn('hardlink_topology',[x['field'] for x in compare(self.a,self.b)['differences']])
 def test_limit(self):
  (self.a/'f').touch()
  with self.assertRaises(ValueError):inventory(self.a,max_entries=0)
 def test_tamper(self):
  r=compare(self.a,self.b);r['status']='PASS';self.assertFalse(verify(r))
 def test_sparse_unverified(self):
  (self.a/'f').write_bytes(b'');(self.b/'f').write_bytes(b'')
  self.assertIn('sparse_hole_map',[x['field'] for x in compare(self.a,self.b)['unverified']])
if __name__=='__main__':unittest.main()
