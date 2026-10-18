import json
import tempfile
import unittest
from pathlib import Path
from native_campaign_manifest_v2039 import create_manifest
from native_verified_batch_v2040 import run_verified_batch
from native_migration_errors import MigrationBlocked

class VerifiedBatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.src = self.root / 'src'; self.dst = self.root / 'dst'
        self.src.mkdir(); self.dst.mkdir()
        (self.src / 'a.txt').write_text('alpha')
        (self.src / 'b.txt').write_text('bravo')
        self.db = self.root / 'journal.sqlite'
        self.manifest = self.root / 'manifest.json'
        create_manifest(self.src, self.dst, self.db, self.manifest)
    def tearDown(self): self.tmp.cleanup()
    def test_batch_copies_and_verifies(self):
        r = run_verified_batch(self.src, self.dst, self.db, self.manifest, offset=0, limit=1)
        self.assertEqual(r['status'], 'BATCH_VERIFIED_POSIX_SUBSET_ONLY')
        self.assertEqual(r['next_offset'], 1)
        self.assertEqual((self.dst/'a.txt').read_text(), 'alpha')
        self.assertFalse(r['cutover_authorized'])
        self.assertFalse(r['acl_fidelity_verified'])
    def test_resume_next_offset(self):
        run_verified_batch(self.src, self.dst, self.db, self.manifest, offset=0, limit=1)
        r = run_verified_batch(self.src, self.dst, self.db, self.manifest, offset=1, limit=1)
        self.assertEqual(r['next_offset'], 2)
        self.assertEqual((self.dst/'b.txt').read_text(), 'bravo')
    def test_wrong_roots_blocked(self):
        with self.assertRaises(MigrationBlocked):
            run_verified_batch(self.root/'src', self.root/'other', self.db, self.manifest)
    def test_bad_offset_rejected(self):
        with self.assertRaises(ValueError):
            run_verified_batch(self.src, self.dst, self.db, self.manifest, offset=-1)
    def test_source_drift_blocks_after_committed_copy(self):
        run_verified_batch(self.src, self.dst, self.db, self.manifest, offset=0, limit=1)
        (self.src/'a.txt').write_text('changed')
        with self.assertRaises(MigrationBlocked):
            run_verified_batch(self.src, self.dst, self.db, self.manifest, offset=0, limit=1)
    def test_existing_target_conflict_not_overwritten(self):
        (self.dst/'a.txt').write_text('do-not-overwrite')
        with self.assertRaises(Exception):
            run_verified_batch(self.src, self.dst, self.db, self.manifest, offset=0, limit=1)
        self.assertEqual((self.dst/'a.txt').read_text(), 'do-not-overwrite')

if __name__ == '__main__': unittest.main()
