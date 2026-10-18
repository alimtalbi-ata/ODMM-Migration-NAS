import json,tempfile,unittest
from pathlib import Path
from native_campaign_manifest_v2039 import create_manifest
from native_fidelity_manifest_v2041 import create_fidelity_manifest,load_fidelity_manifest
from native_verified_batch_v2041 import run_fidelity_batch
from native_migration_errors import MigrationBlocked
class FidelityManifestTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory(); self.r=Path(self.t.name); self.s=self.r/'src'; self.d=self.r/'dst'; self.s.mkdir(); self.d.mkdir(); (self.s/'a').write_text('alpha'); (self.s/'b').write_text('bravo'); self.db=self.r/'db.sqlite'; self.cm=self.r/'campaign_manifest.json'; self.fm=self.r/'fidelity.json'; create_manifest(self.s,self.d,self.db,self.cm); create_fidelity_manifest(self.s,self.d,self.db,self.fm)
 def tearDown(self): self.t.cleanup()
 def test_manifest_fingerprint(self): self.assertEqual(load_fidelity_manifest(self.fm)['fingerprints']['a']['sha256'],__import__('hashlib').sha256(b'alpha').hexdigest())
 def test_batch_verifies_copy(self):
  r=run_fidelity_batch(self.s,self.d,self.db,self.fm,offset=0,limit=1); self.assertEqual(r['status'],'BATCH_FINGERPRINT_VERIFIED_POSIX_SUBSET_ONLY'); self.assertEqual(r['next_offset'],1); self.assertFalse(r['cutover_authorized'])
 def test_resume(self):
  run_fidelity_batch(self.s,self.d,self.db,self.fm,offset=0,limit=1); r=run_fidelity_batch(self.s,self.d,self.db,self.fm,offset=1,limit=1); self.assertEqual(r['next_offset'],2)
 def test_source_drift_blocks_before_copy(self):
  (self.s/'a').write_text('changed')
  with self.assertRaises(MigrationBlocked): run_fidelity_batch(self.s,self.d,self.db,self.fm,offset=0,limit=1)
  self.assertFalse((self.d/'a').exists())
 def test_manifest_tamper(self):
  x=json.loads(self.fm.read_text()); x['payload']['fingerprints']['a']['size']=999; self.fm.write_text(json.dumps(x))
  with self.assertRaises(MigrationBlocked): load_fidelity_manifest(self.fm)
 def test_target_conflict_preserved(self):
  (self.d/'a').write_text('keep')
  with self.assertRaises(Exception): run_fidelity_batch(self.s,self.d,self.db,self.fm,offset=0,limit=1)
  self.assertEqual((self.d/'a').read_text(),'keep')
 def test_wrong_root_blocks(self):
  with self.assertRaises(MigrationBlocked): run_fidelity_batch(self.s,self.r/'wrong',self.db,self.fm)
 def test_invalid_offset(self):
  with self.assertRaises(ValueError): run_fidelity_batch(self.s,self.d,self.db,self.fm,offset=-1)
 def test_zero_limit(self):
  r=run_fidelity_batch(self.s,self.d,self.db,self.fm,limit=0); self.assertEqual(r['processed_count'],0)
if __name__=='__main__': unittest.main()
