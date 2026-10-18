import os
import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked

class DescriptorIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.src=root/'src'; self.dst=root/'dst'
        (self.src/'sub').mkdir(parents=True); (self.dst/'sub').mkdir(parents=True)
        (self.src/'sub'/'a').write_bytes(b'hello'*100)
        self.db=root/'journal.sqlite'

    def test_nested_copy_and_verify(self):
        with NativePosixMigration(self.src,self.dst,self.db) as engine:
            self.assertEqual(engine.copy('sub/a')['status'],'COPIED_VERIFIED')
            self.assertEqual(engine.verify('sub/a')['status'],'VERIFIED_POSIX_SUBSET_ONLY')

    def test_source_parent_swap_before_publish(self):
        def swap():
            (self.src/'sub').rename(self.src/'old')
            (self.src/'sub').mkdir()
            (self.src/'sub'/'a').write_bytes(b'evil')
        with NativePosixMigration(self.src,self.dst,self.db) as engine:
            with self.assertRaisesRegex(MigrationBlocked,'DIRECTORY_REPLACED'):
                engine.copy('sub/a',after_temp_sync=swap)
            self.assertFalse((self.dst/'sub'/'a').exists())

    def test_target_parent_swap_before_publish(self):
        def swap():
            (self.dst/'sub').rename(self.dst/'old')
            (self.dst/'sub').mkdir()
        with NativePosixMigration(self.src,self.dst,self.db) as engine:
            with self.assertRaisesRegex(MigrationBlocked,'DIRECTORY_REPLACED'):
                engine.copy('sub/a',after_temp_sync=swap)
            self.assertFalse((self.dst/'sub'/'a').exists())

    def test_parent_swap_after_publish_leaves_intent(self):
        def swap():
            (self.dst/'sub').rename(self.dst/'old')
            (self.dst/'sub').mkdir()
        with NativePosixMigration(self.src,self.dst,self.db) as engine:
            with self.assertRaisesRegex(MigrationBlocked,'DIRECTORY_REPLACED'):
                engine.copy('sub/a',after_publish=swap)
            self.assertTrue((self.dst/'old'/'a').exists())
            with self.assertRaisesRegex(MigrationBlocked,'PENDING_INTENT'):
                engine.copy('sub/a')

    def test_symlink_parent_after_init(self):
        (self.src/'sub').rename(self.src/'old')
        (self.src/'sub').symlink_to('old',target_is_directory=True)
        with NativePosixMigration(self.src,self.dst,self.db) as engine:
            with self.assertRaises(MigrationBlocked): engine.copy('sub/a')

    def test_symlink_target_after_init(self):
        (self.dst/'sub').rename(self.dst/'old')
        (self.dst/'sub').symlink_to('old',target_is_directory=True)
        with NativePosixMigration(self.src,self.dst,self.db) as engine:
            with self.assertRaises(MigrationBlocked): engine.copy('sub/a')

    def test_reconcile_nested_after_publish_crash(self):
        with NativePosixMigration(self.src,self.dst,self.db) as engine:
            with self.assertRaises(RuntimeError):
                engine.copy('sub/a',after_publish=lambda: (_ for _ in ()).throw(RuntimeError('crash')))
            self.assertEqual(engine.reconcile('sub/a',operator_confirmed=True)['status'],'RECONCILED_VERIFIED')

    def test_verify_detects_symlink_replacement(self):
        with NativePosixMigration(self.src,self.dst,self.db) as engine:
            engine.copy('sub/a')
            (self.dst/'sub'/'a').unlink()
            (self.dst/'sub'/'a').symlink_to(self.src/'sub'/'a')
            with self.assertRaises(MigrationBlocked): engine.verify('sub/a')
