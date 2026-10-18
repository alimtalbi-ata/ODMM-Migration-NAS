"""Subprocess crash/restart tests for the native POSIX transactional engine."""
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked

class CrashDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.src = self.base/'src'; self.dst = self.base/'dst'
        self.src.mkdir(); self.dst.mkdir()
        self.db = self.base/'ledger.sqlite'
        (self.src/'data.bin').write_bytes(b'ODMM' * 8192)

    def child(self, hook):
        code = '''import os,sys
from native_posix_migration import NativePosixMigration
m=NativePosixMigration(sys.argv[1],sys.argv[2],sys.argv[3])
try:
 m.copy('data.bin', **{sys.argv[4]:lambda:os._exit(77)})
finally:m.close()
'''
        env = dict(os.environ)
        env['PYTHONPATH'] = str(Path(__file__).resolve().parent)
        return subprocess.run([sys.executable,'-c',code,str(self.src),str(self.dst),str(self.db),hook],env=env,timeout=15,capture_output=True)

    def test_crash_after_temp_sync_leaves_no_committed_file(self):
        p=self.child('after_temp_sync')
        self.assertEqual(p.returncode,77,p.stderr)
        with NativePosixMigration(self.src,self.dst,self.db) as m:
            self.assertFalse((self.dst/'data.bin').exists())
            self.assertEqual(m.copy('data.bin')['status'],'COPIED_VERIFIED')
            self.assertEqual(m.verify('data.bin')['status'],'VERIFIED_POSIX_SUBSET_ONLY')

    def test_crash_after_publish_requires_human_reconciliation(self):
        p=self.child('after_publish')
        self.assertEqual(p.returncode,77,p.stderr)
        with NativePosixMigration(self.src,self.dst,self.db) as m:
            with self.assertRaisesRegex(MigrationBlocked,'PENDING_INTENT'):
                m.copy('data.bin')
            with self.assertRaisesRegex(MigrationBlocked,'OPERATOR_CONFIRMATION'):
                m.reconcile('data.bin')
            self.assertEqual(m.reconcile('data.bin',operator_confirmed=True)['status'],'RECONCILED_VERIFIED')
            self.assertEqual(m.copy('data.bin')['status'],'ALREADY_VERIFIED')

    def test_crash_after_publish_modified_target_is_blocked(self):
        self.assertEqual(self.child('after_publish').returncode,77)
        (self.dst/'data.bin').write_bytes(b'corrupted')
        with NativePosixMigration(self.src,self.dst,self.db) as m:
            with self.assertRaisesRegex(MigrationBlocked,'RECONCILIATION_CONTENT_MISMATCH'):
                m.reconcile('data.bin',operator_confirmed=True)

    def test_intent_is_durable_before_publish_hook(self):
        self.assertEqual(self.child('after_publish').returncode,77)
        db=sqlite3.connect(self.db)
        try:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM intents').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM files').fetchone()[0],0)
        finally:db.close()

    def test_second_process_cannot_overwrite_published_file(self):
        self.assertEqual(self.child('after_publish').returncode,77)
        self.assertEqual(self.child('after_publish').returncode,1)
        self.assertEqual((self.dst/'data.bin').read_bytes(),b'ODMM'*8192)

if __name__=='__main__':unittest.main()
