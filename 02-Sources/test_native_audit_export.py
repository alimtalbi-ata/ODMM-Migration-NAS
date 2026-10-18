import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from native_orphan_audit import append
from native_audit_export import build_bundle,verify_bundle,checkpoint,export_file
from native_migration_errors import MigrationBlocked
KEY=b'X'*32
class AuditExportTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:',isolation_level=None)
    def tearDown(self): self.db.close()
    def add(self): append(self.db,KEY,kind='REVIEW',review_id='id',path='p',operator='op',rationale='reason')
    def test_empty(self): self.assertEqual(verify_bundle(build_bundle(self.db,KEY),KEY)['events'],0)
    def test_two_events(self):
        self.add();self.add();self.assertEqual(verify_bundle(build_bundle(self.db,KEY),KEY)['events'],2)
    def test_wrong_key(self):
        self.add()
        with self.assertRaises(MigrationBlocked): verify_bundle(build_bundle(self.db,KEY),b'Y'*32)
    def test_tampered_event(self):
        self.add();bundle=build_bundle(self.db,KEY);bundle['payload']['events'][0]['event_json']='{}'
        with self.assertRaises(MigrationBlocked): verify_bundle(bundle,KEY)
    def test_truncated_with_old_checkpoint(self):
        self.add();self.add();original=build_bundle(self.db,KEY);cp=checkpoint(original,KEY)
        self.db.execute('DELETE FROM orphan_audit_chain WHERE seq=2')
        shorter=build_bundle(self.db,KEY)
        with self.assertRaises(MigrationBlocked): verify_bundle(shorter,KEY,trusted_checkpoint=cp)
    def test_fork_with_old_checkpoint(self):
        self.add();cp=checkpoint(build_bundle(self.db,KEY),KEY)
        self.db.execute('DELETE FROM orphan_audit_chain')
        append(self.db,KEY,kind='DIFFERENT',review_id='id',path='p',operator='op',rationale='reason')
        with self.assertRaises(MigrationBlocked): verify_bundle(build_bundle(self.db,KEY),KEY,trusted_checkpoint=cp)
    def test_export_no_overwrite(self):
        self.add()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'evidence.json'
            result=export_file(self.db,KEY,path)
            self.assertEqual(verify_bundle(json.loads(path.read_text()),KEY)['events'],1)
            self.assertEqual(result['events'],1)
            with self.assertRaises(MigrationBlocked): export_file(self.db,KEY,path)
    def test_checkpoint_tamper(self):
        cp=checkpoint(build_bundle(self.db,KEY),KEY);cp['payload']['count']=99
        with self.assertRaises(MigrationBlocked): verify_bundle(build_bundle(self.db,KEY),KEY,trusted_checkpoint=cp)
if __name__=='__main__': unittest.main()
