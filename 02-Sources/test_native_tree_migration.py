import os
import tempfile
import unittest
from pathlib import Path
from native_tree_migration import NativeTreeMigration
from native_posix_migration import MigrationBlocked

class NativeTreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.src=root/'src'; self.dst=root/'dst'; self.src.mkdir(); self.dst.mkdir()
        (self.src/'a').write_bytes(b'a')
        (self.src/'sub').mkdir(); (self.dst/'sub').mkdir()
        (self.src/'sub'/'b').write_bytes(b'b')
        self.db=root/'ledger.sqlite'
    def engine(self):
        return NativeTreeMigration(self.src,self.dst,self.db)
    def test_inventory(self):
        with self.engine() as e: self.assertEqual(e.inventory(),['a','sub/b'])
    def test_copy_and_verify(self):
        with self.engine() as e:
            self.assertEqual(e.run()['processed_count'],2)
            self.assertEqual(e.verify_all()['count'],2)
    def test_idempotent(self):
        with self.engine() as e:
            e.run(); self.assertTrue(all(x['status']=='ALREADY_VERIFIED' for x in e.run()['results']))
    def test_limited_batch_resume(self):
        with self.engine() as e:
            self.assertEqual(e.run(limit=1)['processed_count'],1)
            self.assertEqual(e.run()['processed_count'],2)
    def test_missing_target_directory_blocks(self):
        (self.dst/'sub').rmdir()
        with self.engine() as e:
            with self.assertRaises(MigrationBlocked): e.run()
    def test_symlink_file_blocks(self):
        (self.src/'evil').symlink_to(self.src/'a')
        with self.engine() as e:
            with self.assertRaises(MigrationBlocked): e.inventory()
    def test_symlink_directory_blocks(self):
        (self.src/'alias').symlink_to(self.src/'sub',target_is_directory=True)
        with self.engine() as e:
            with self.assertRaises(MigrationBlocked): e.inventory()
    def test_fifo_blocks(self):
        os.mkfifo(self.src/'fifo')
        with self.engine() as e:
            with self.assertRaises(MigrationBlocked): e.inventory()
    def test_target_drift_blocks(self):
        with self.engine() as e:
            e.run(); (self.dst/'a').write_bytes(b'corrupt')
            with self.assertRaises(MigrationBlocked): e.verify_all()
    def test_no_cutover(self):
        with self.engine() as e:
            result=e.run(); self.assertFalse(result['cutover_authorized']); self.assertFalse(result['acl_fidelity_verified'])
    def test_invalid_limit(self):
        with self.engine() as e:
            with self.assertRaises(ValueError): e.run(limit=-1)
    def test_existing_target_blocks(self):
        (self.dst/'a').write_bytes(b'old')
        with self.engine() as e:
            with self.assertRaises(MigrationBlocked): e.run()

if __name__=='__main__': unittest.main()
