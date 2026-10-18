import json, tempfile, unittest
from pathlib import Path
from native_campaign_manifest_v2039 import create_manifest, load_manifest, run_batch
from native_migration_errors import MigrationBlocked

class CampaignManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.src=self.root/'src'; self.dst=self.root/'dst'
        self.src.mkdir(); self.dst.mkdir(); (self.src/'a').write_bytes(b'a')
        (self.src/'b').write_bytes(b'b'); self.db=self.root/'ledger.sqlite'; self.manifest=self.root/'campaign.json'
    def create(self): return create_manifest(self.src,self.dst,self.db,self.manifest)
    def test_create_and_digest(self):
        r=self.create(); p=load_manifest(self.manifest); self.assertEqual(r['count'],2); self.assertEqual(p['files'],['a','b'])
    def test_create_only(self):
        self.create()
        with self.assertRaises(MigrationBlocked): self.create()
    def test_resume_explicit_offset(self):
        self.create(); r=run_batch(self.src,self.dst,self.db,self.manifest,offset=0,limit=1)
        self.assertEqual(r['next_offset'],1); r2=run_batch(self.src,self.dst,self.db,self.manifest,offset=1)
        self.assertEqual(r2['processed_count'],1)
    def test_manifest_tamper_blocked(self):
        self.create(); env=json.loads(self.manifest.read_text()); env['payload']['files'].append('evil'); self.manifest.write_text(json.dumps(env))
        with self.assertRaises(MigrationBlocked): load_manifest(self.manifest)
    def test_inventory_drift_blocks_resume(self):
        self.create(); (self.src/'c').write_bytes(b'c')
        with self.assertRaises(MigrationBlocked): run_batch(self.src,self.dst,self.db,self.manifest)
    def test_missing_source_file_blocks(self):
        self.create(); (self.src/'b').unlink()
        with self.assertRaises(MigrationBlocked): run_batch(self.src,self.dst,self.db,self.manifest)
    def test_root_mismatch_blocks(self):
        self.create(); other=self.root/'other'; other.mkdir()
        with self.assertRaises(MigrationBlocked): run_batch(other,self.dst,self.db,self.manifest)
    def test_bad_offset(self):
        self.create()
        with self.assertRaises(ValueError): run_batch(self.src,self.dst,self.db,self.manifest,offset=-1)
    def test_zero_limit(self):
        self.create(); r=run_batch(self.src,self.dst,self.db,self.manifest,limit=0); self.assertEqual(r['processed_count'],0)
    def test_no_cutover(self):
        r=self.create(); self.assertFalse(r['cutover_authorized']); self.assertFalse(r['acl_fidelity_verified'])

if __name__=='__main__': unittest.main()
