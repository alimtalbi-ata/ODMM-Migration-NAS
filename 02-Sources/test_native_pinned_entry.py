import os
import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked
from native_dirfd_guard import parent_fd

class PinnedEntryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.src=self.root/'src'; self.dst=self.root/'dst'
        self.src.mkdir(); self.dst.mkdir()
        (self.src/'a').write_bytes(b'original')
        self.db=self.root/'db.sqlite'

    def test_parent_fd_stays_on_pinned_root_after_rename(self):
        fd=os.open(self.src, os.O_RDONLY|os.O_DIRECTORY)
        self.addCleanup(os.close,fd)
        self.src.rename(self.root/'old')
        self.src.mkdir(); (self.src/'a').write_bytes(b'evil')
        with parent_fd(self.src,'a',root_fd=fd) as (directory,name):
            f=os.open(name,os.O_RDONLY,dir_fd=directory)
            try:self.assertEqual(os.read(f,100),b'original')
            finally:os.close(f)

    def test_same_content_replacement_after_publish_refused(self):
        with NativePosixMigration(self.src,self.dst,self.db) as engine:
            def replace():
                (self.src/'a').unlink()
                (self.src/'replacement').write_bytes(b'original')
                (self.src/'replacement').rename(self.src/'a')
            with self.assertRaisesRegex(MigrationBlocked,'SOURCE_ENTRY_REPLACED'):
                engine.copy('a',after_publish=replace)
            self.assertEqual(engine.db.execute('SELECT count(*) FROM files').fetchone()[0],0)
            self.assertEqual(engine.db.execute('SELECT count(*) FROM intents').fetchone()[0],1)

    def test_normal_copy_and_verify(self):
        with NativePosixMigration(self.src,self.dst,self.db) as engine:
            self.assertEqual(engine.copy('a')['status'],'COPIED_VERIFIED')
            self.assertEqual(engine.verify('a')['status'],'VERIFIED_POSIX_SUBSET_ONLY')
