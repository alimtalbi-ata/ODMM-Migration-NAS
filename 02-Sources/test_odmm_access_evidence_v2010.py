import os, tempfile, unittest
from pathlib import Path
from odmm_access_evidence_v2010 import collect_read_observation, compare_access_evidence
from readonly_access_probe import AccessProbeError

class AccessEvidence2010(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);(self.root/'a').write_text('abc')
 def tearDown(self):self.tmp.cleanup()
 def obs(self,outcome='ALLOW',attested=True):return {'outcome':outcome,'server_attested':attested,'identity_attested':attested}
 def test_read_only_observation(self):
  before=(self.root/'a').read_bytes();r=collect_read_observation(self.root,'a',expected_euid=os.geteuid());self.assertEqual(r['outcome'],'OPEN_READ_SUCCEEDED');self.assertEqual(before,(self.root/'a').read_bytes());self.assertFalse(r['server_attested'])
 def test_wrong_identity_rejected(self):
  with self.assertRaises(AccessProbeError):collect_read_observation(self.root,'a',expected_euid=os.geteuid()+1)
 def test_symlink_rejected(self):
  (self.root/'link').symlink_to('a')
  with self.assertRaises(AccessProbeError):collect_read_observation(self.root,'link',expected_euid=os.geteuid())
 def test_equal_evidence_never_cutover(self):
  a={('a','uid:1','read'):self.obs()};r=compare_access_evidence(a,a,required_rights=('read',));self.assertFalse(r['cutover_authorized']);self.assertEqual(r['status'],'EVIDENCE_MATCH_REQUIRES_INDEPENDENT_QUALIFICATION')
 def test_mismatch(self):
  a={('a','uid:1','read'):self.obs()};b={('a','uid:1','read'):self.obs('DENY')};self.assertEqual(compare_access_evidence(a,b,required_rights=('read',))['status'],'BLOCKED')
 def test_missing_target(self):
  a={('a','uid:1','read'):self.obs()};self.assertEqual(compare_access_evidence(a,{},required_rights=('read',))['status'],'BLOCKED')
 def test_missing_rights(self):
  a={('a','uid:1','read'):self.obs()};self.assertEqual(compare_access_evidence(a,a)['status'],'BLOCKED')
 def test_unattested(self):
  a={('a','uid:1','read'):self.obs(attested=False)};self.assertEqual(compare_access_evidence(a,a,required_rights=('read',))['status'],'BLOCKED')
 def test_invalid_key(self):
  a={('../escape','uid:1','read'):self.obs()};self.assertEqual(compare_access_evidence(a,a,required_rights=('read',))['status'],'BLOCKED')
 def test_stable_digest(self):
  a={('a','uid:1','read'):self.obs()};self.assertEqual(compare_access_evidence(a,a,required_rights=('read',))['evidence_sha256'],compare_access_evidence(a,a,required_rights=('read',))['evidence_sha256'])
 def test_empty(self):self.assertEqual(compare_access_evidence({}, {})['status'],'BLOCKED')
if __name__=='__main__':unittest.main()
