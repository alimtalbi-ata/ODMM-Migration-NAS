import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from native_cockpit_audit_operations import verify_access_audit,export_anchor,inspect_legacy_audit
from native_benchmark_cockpit_adapter import serve_evidence
from native_benchmark_evidence_manifest import create_manifest

class OperationsTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name);self.db=self.root/'access.db';self.key=b'Q'*32
        manifest=create_manifest(self.root/'missing',self.root,keys={'a':b'A'*32},manifest_key=b'B'*32,key_id='m')
        serve_evidence(manifest,principal={'authenticated':True,'subject':'tester','roles':['evidence_viewer']},manifest_keys={'m':b'B'*32},audit_db=self.db,audit_key=self.key)
    def test_verify(self):self.assertEqual(verify_access_audit(self.db,audit_key=self.key)['count'],1)
    def test_wrong_key(self):
        with self.assertRaisesRegex(ValueError,'AUDIT_CHAIN_INVALID'):verify_access_audit(self.db,audit_key=b'Z'*32)
    def test_trusted_head(self):
        head=verify_access_audit(self.db,audit_key=self.key)['head_sha256']
        self.assertEqual(verify_access_audit(self.db,audit_key=self.key,trusted_head=head)['count'],1)
        with self.assertRaisesRegex(ValueError,'AUDIT_TRUSTED_HEAD_MISMATCH'):verify_access_audit(self.db,audit_key=self.key,trusted_head='0'*64)
    def test_export(self):
        path=self.root/'anchor.json'
        result=export_anchor(self.db,path,audit_key=self.key)
        self.assertEqual(json.loads(path.read_text())['head_sha256'],result['head_sha256'])
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        with self.assertRaises(FileExistsError):export_anchor(self.db,path,audit_key=self.key)
    def test_legacy_quarantine(self):
        status=inspect_legacy_audit(self.db)
        self.assertEqual(status['migration_state'],'QUARANTINED_REVIEW_REQUIRED')
        self.assertFalse(status['legacy_authenticated'])
    def test_tamper_blocks_export(self):
        with sqlite3.connect(self.db) as conn:conn.execute("UPDATE evidence_access_log SET action='tampered'")
        with self.assertRaisesRegex(ValueError,'AUDIT_CHAIN_INVALID'):export_anchor(self.db,self.root/'anchor',audit_key=self.key)
        self.assertFalse((self.root/'anchor').exists())
    def test_symlink(self):
        link=self.root/'link';link.symlink_to(self.db)
        with self.assertRaisesRegex(ValueError,'AUDIT_PATH_SYMLINK'):verify_access_audit(link,audit_key=self.key)
    def test_no_new_db(self):
        with self.assertRaises(FileNotFoundError):verify_access_audit(self.root/'missing.db',audit_key=self.key)
        self.assertFalse((self.root/'missing.db').exists())
if __name__=='__main__':unittest.main()
