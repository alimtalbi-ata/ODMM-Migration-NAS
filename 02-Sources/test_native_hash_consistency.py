import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import native_posix_migration as migration


class HashConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.src, self.dst = self.root/'src', self.root/'dst'
        self.src.mkdir(); self.dst.mkdir()
        (self.src/'a').write_bytes(b'original')
        self.db = self.root/'registry.sqlite'

    def test_hash_detects_in_place_modification(self):
        p = self.src/'a'
        fd = os.open(p, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        original = migration._hash_fd
        def mutate(handle):
            value = original(handle)
            p.write_bytes(b'changed!')
            return value
        with patch.object(migration, '_hash_fd', side_effect=mutate):
            with self.assertRaisesRegex(migration.MigrationBlocked, 'FILE_CHANGED_DURING_HASH'):
                migration._verified_hash(fd)

    def test_verify_detects_destination_replacement_after_hash(self):
        with migration.NativePosixMigration(self.src, self.dst, self.db) as engine:
            engine.copy('a')
            original = migration._verified_hash
            def swap(fd, **kw):
                value = original(fd, **kw)
                if os.fstat(fd).st_ino == (self.dst/'a').stat().st_ino:
                    (self.dst/'a').unlink()
                    (self.dst/'a').write_bytes(b'original')
                return value
            with patch.object(migration, '_verified_hash', side_effect=swap):
                with self.assertRaisesRegex(migration.MigrationBlocked, 'SOURCE_ENTRY_REPLACED'):
                    engine.verify('a')

    def test_reconcile_detects_destination_replacement_after_hash(self):
        with migration.NativePosixMigration(self.src, self.dst, self.db) as engine:
            def crash():
                raise RuntimeError('simulated interruption')
            with self.assertRaises(RuntimeError):
                engine.copy('a', after_publish=crash)
            original = migration._verified_hash
            def swap(fd, **kw):
                value = original(fd, **kw)
                if os.fstat(fd).st_ino == (self.dst/'a').stat().st_ino:
                    (self.dst/'a').unlink()
                    (self.dst/'a').write_bytes(b'original')
                return value
            with patch.object(migration, '_verified_hash', side_effect=swap):
                with self.assertRaisesRegex(migration.MigrationBlocked, 'SOURCE_ENTRY_REPLACED'):
                    engine.reconcile('a', operator_confirmed=True)
            self.assertEqual(engine.db.execute('SELECT COUNT(*) FROM intents').fetchone()[0], 1)
