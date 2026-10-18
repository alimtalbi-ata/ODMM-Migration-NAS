import os
import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked

class RootPinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.src = self.base/'source'; self.dst = self.base/'target'
        self.src.mkdir(); self.dst.mkdir()
        (self.src/'a').write_bytes(b'data')
        self.db = self.base/'db.sqlite'

    def test_copy_normal(self):
        with NativePosixMigration(self.src,self.dst,self.db) as e:
            self.assertEqual(e.copy('a')['status'],'COPIED_VERIFIED')
            self.assertEqual(e.verify('a')['status'],'VERIFIED_POSIX_SUBSET_ONLY')

    def test_source_root_swap_blocks_copy(self):
        with NativePosixMigration(self.src,self.dst,self.db) as e:
            self.src.rename(self.base/'oldsrc')
            self.src.mkdir(); (self.src/'a').write_bytes(b'other')
            with self.assertRaisesRegex(MigrationBlocked,'ROOT_REPLACED'): e.copy('a')

    def test_target_root_swap_blocks_copy(self):
        with NativePosixMigration(self.src,self.dst,self.db) as e:
            self.dst.rename(self.base/'olddst')
            self.dst.mkdir()
            with self.assertRaisesRegex(MigrationBlocked,'ROOT_REPLACED'): e.copy('a')

    def test_target_root_swap_blocks_verify(self):
        with NativePosixMigration(self.src,self.dst,self.db) as e:
            e.copy('a'); self.dst.rename(self.base/'olddst'); self.dst.mkdir()
            with self.assertRaisesRegex(MigrationBlocked,'ROOT_REPLACED'): e.verify('a')

    def test_root_symlink_refused(self):
        alias=self.base/'alias'; alias.symlink_to(self.src, target_is_directory=True)
        with self.assertRaisesRegex(MigrationBlocked,'SYMLINK_ROOT'):
            NativePosixMigration(alias,self.dst,self.db)

    def test_target_root_symlink_refused(self):
        alias=self.base/'alias'; alias.symlink_to(self.dst, target_is_directory=True)
        with self.assertRaisesRegex(MigrationBlocked,'SYMLINK_ROOT'):
            NativePosixMigration(self.src,alias,self.db)

    def test_missing_root_blocks_verify(self):
        with NativePosixMigration(self.src,self.dst,self.db) as e:
            e.copy('a'); self.dst.rename(self.base/'olddst')
            with self.assertRaisesRegex(MigrationBlocked,'ROOT_MISSING_OR_REPLACED'): e.verify('a')

    def test_source_mutation_after_publish_blocks_commit(self):
        with NativePosixMigration(self.src,self.dst,self.db) as e:
            def mutate(): (self.src/'a').write_bytes(b'changed')
            with self.assertRaisesRegex(MigrationBlocked,'SOURCE_CHANGED_AFTER_PUBLICATION'):
                e.copy('a',after_publish=mutate)
            self.assertEqual(e.db.execute('SELECT count(*) FROM files').fetchone()[0],0)
            self.assertEqual(e.db.execute('SELECT count(*) FROM intents').fetchone()[0],1)
