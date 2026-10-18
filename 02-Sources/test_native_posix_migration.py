import os
import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked

class NativeMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name); self.src=root/'src'; self.dst=root/'dst'; self.src.mkdir(); self.dst.mkdir()
        self.db=root/'journal.sqlite'; (self.src/'a').write_bytes(b'abc'*1000)
    def engine(self): return NativePosixMigration(self.src,self.dst,self.db)
    def test_copy_and_verify(self):
        with self.engine() as e:
            self.assertEqual(e.copy('a')['status'],'COPIED_VERIFIED'); self.assertEqual(e.verify('a')['status'],'VERIFIED_POSIX_SUBSET_ONLY')
    def test_resume(self):
        with self.engine() as e: e.copy('a')
        with self.engine() as e: self.assertEqual(e.copy('a')['status'],'ALREADY_VERIFIED')
    def test_tamper(self):
        with self.engine() as e:
            e.copy('a'); (self.dst/'a').write_bytes(b'wrong')
            with self.assertRaises(MigrationBlocked): e.verify('a')
    def test_existing_target(self):
        (self.dst/'a').write_bytes(b'other')
        with self.engine() as e, self.assertRaises(MigrationBlocked): e.copy('a')
    def test_symlink_source(self):
        (self.src/'b').symlink_to('a')
        with self.engine() as e, self.assertRaises(MigrationBlocked): e.copy('b')
    def test_symlink_target(self):
        (self.dst/'a').symlink_to(self.src/'a')
        with self.engine() as e, self.assertRaises(MigrationBlocked): e.copy('a')
    def test_traversal(self):
        with self.engine() as e, self.assertRaises(MigrationBlocked): e.copy('../a')
    def test_nested_symlink(self):
        (self.src/'link').symlink_to(self.src, target_is_directory=True)
        with self.engine() as e, self.assertRaises(MigrationBlocked): e.copy('link/a')
    def test_interruption(self):
        def interrupt(): raise RuntimeError('power loss simulation')
        with self.engine() as e:
            with self.assertRaises(RuntimeError): e.copy('a',after_temp_sync=interrupt)
            self.assertFalse((self.dst/'a').exists()); self.assertEqual(e.copy('a')['status'],'COPIED_VERIFIED')
    def test_source_mutation(self):
        def mutate(): (self.src/'a').write_bytes(b'new')
        with self.engine() as e, self.assertRaises(MigrationBlocked): e.copy('a',after_temp_sync=mutate)
    def test_source_change_after_commit(self):
        with self.engine() as e:
            e.copy('a'); (self.src/'a').write_bytes(b'new')
            with self.assertRaises(MigrationBlocked): e.copy('a')
    def test_mode_preserved(self):
        os.chmod(self.src/'a',0o640)
        with self.engine() as e:
            e.copy('a'); self.assertEqual((self.dst/'a').stat().st_mode & 0o777,0o640)
