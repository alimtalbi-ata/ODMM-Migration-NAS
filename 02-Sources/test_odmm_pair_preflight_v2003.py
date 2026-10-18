import tempfile, unittest
from pathlib import Path
from odmm_storage_catalog_v2002 import solutions
from odmm_pair_preflight_v2003 import preflight,PreflightError
class PreflightTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.a=Path(self.tmp.name)/'a'; self.b=Path(self.tmp.name)/'b'; self.a.mkdir(); self.b.mkdir()
  self.src=solutions(vendor='NetApp')[0]; self.dst=solutions(vendor='Dell')[0]
 def test_read_only_and_uncertified(self):
  (self.a/'file').write_bytes(b'data'); result=preflight(self.src,self.dst,self.a,self.b,protocol='NFS')
  self.assertEqual(result['source']['counts']['files'],1)
  self.assertFalse(result['cutover_authorized']); self.assertEqual((self.a/'file').read_bytes(),b'data')
  self.assertEqual(result['fidelity_checks']['acl'],'UNVERIFIED')
 def test_symlink_flagged(self):
  (self.a/'link').symlink_to('missing')
  result=preflight(self.src,self.dst,self.a,self.b,protocol='NFS')
  self.assertIn('NATIVE_TREE_ENGINE_REJECTS_NONREGULAR_ENTRIES',result['warnings'])
 def test_s3_not_falsely_inspected(self):
  s=solutions(vendor='NetApp')[1]; t=solutions(vendor='Cloudian')[0]
  result=preflight(s,t,'unused','unused',protocol='S3')
  self.assertEqual(result['status'],'S3_API_PREFLIGHT_REQUIRED'); self.assertFalse(result['cutover_authorized'])
 def test_limits(self):
  (self.a/'one').touch(); (self.a/'two').touch()
  with self.assertRaisesRegex(PreflightError,'INVENTORY_LIMIT'): preflight(self.src,self.dst,self.a,self.b,protocol='NFS',max_entries=1)
 def test_invalid_roots(self):
  with self.assertRaisesRegex(PreflightError,'INVALID_ROOT'): preflight(self.src,self.dst,self.a/'absent',self.b,protocol='NFS')
 def test_unshared_protocol(self):
  with self.assertRaisesRegex(PreflightError,'PROTOCOL_NOT_SHARED'): preflight(self.src,solutions(vendor='Cloudian')[0],self.a,self.b,protocol='NFS')
if __name__=='__main__': unittest.main()
