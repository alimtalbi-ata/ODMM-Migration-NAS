import multiprocessing
import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked

class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
        p=Path(self.t.name); self.src=p/'source'; self.dst=p/'target'; self.src.mkdir(); self.dst.mkdir(); self.db=p/'db.sqlite'
        (self.src/'a').write_bytes(b'hello'*100)
    def engine(self): return NativePosixMigration(self.src,self.dst,self.db)
    def crash(self):
        with self.engine() as e:
            with self.assertRaises(RuntimeError):
                e.copy('a',after_publish=lambda: (_ for _ in ()).throw(RuntimeError('crash')))
    def test_recover(self):
        self.crash()
        with self.engine() as e:
            with self.assertRaises(MigrationBlocked): e.copy('a')
            self.assertEqual(e.reconcile('a',operator_confirmed=True)['status'],'RECONCILED_VERIFIED')
            self.assertEqual(e.verify('a')['status'],'VERIFIED_POSIX_SUBSET_ONLY')
    def test_confirmation(self):
        self.crash()
        with self.engine() as e, self.assertRaises(MigrationBlocked): e.reconcile('a')
    def test_tamper(self):
        self.crash(); (self.dst/'a').write_bytes(b'wrong')
        with self.engine() as e, self.assertRaises(MigrationBlocked): e.reconcile('a',operator_confirmed=True)
    def test_missing(self):
        with self.engine() as e, self.assertRaises(MigrationBlocked): e.reconcile('a',operator_confirmed=True)
    def test_source_drift(self):
        self.crash(); (self.src/'a').write_bytes(b'changed')
        with self.engine() as e, self.assertRaises(MigrationBlocked): e.reconcile('a',operator_confirmed=True)
    def test_no_overwrite(self):
        with self.engine() as e:
            e.copy('a')
            with self.assertRaises(MigrationBlocked): e.reconcile('a',operator_confirmed=True)
    def test_persistent_intent(self):
        self.crash()
        with self.engine() as e:
            self.assertEqual(e.db.execute('SELECT count(*) FROM intents').fetchone()[0],1)
    def test_copy_regular(self):
        with self.engine() as e: self.assertEqual(e.copy('a')['status'],'COPIED_VERIFIED')
