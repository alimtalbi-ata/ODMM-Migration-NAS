import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ldaps_external_anchor import ExternalPolicyAnchor, ExternalAnchorError

class FakeRBAC:
    def __init__(self):
        self.db=sqlite3.connect(':memory:',isolation_level=None)
        self.db.execute('CREATE TABLE ldaps_rbac_directory_freshness (id INTEGER PRIMARY KEY,synced_at INTEGER,max_age_seconds INTEGER)')
        self.db.execute('INSERT INTO ldaps_rbac_directory_freshness VALUES(1,100,200)')
    def verify(self):return {'count':0}

class AnchorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.rbac=FakeRBAC();self.addCleanup(self.rbac.db.close)
        self.anchor=ExternalPolicyAnchor(self.rbac,anchor_path=Path(self.tmp.name)/'anchor.json',key=b'x'*32)
        self.audit={'events':1,'last_hash':'a'*64}
        self.patcher=patch('ldaps_external_anchor.AuditedFreshnessPolicy')
        mocked=self.patcher.start();self.addCleanup(self.patcher.stop)
        mocked.return_value.verify.side_effect=lambda:self.audit.copy()
    def test_roundtrip(self):
        self.anchor.checkpoint();self.assertEqual(self.anchor.verify()['status'],'EXTERNAL_ANCHOR_VERIFIED')
    def test_missing(self):
        with self.assertRaisesRegex(ExternalAnchorError,'ANCHOR_MISSING'):self.anchor.verify()
    def test_key_too_short(self):
        with self.assertRaisesRegex(ExternalAnchorError,'KEY_TOO_SHORT'):ExternalPolicyAnchor(self.rbac,anchor_path='x',key=b'a')
    def test_tampered_signature(self):
        self.anchor.checkpoint();p=self.anchor.path;v=json.loads(p.read_text());v['hmac_sha256']='0'*64;p.write_text(json.dumps(v))
        with self.assertRaisesRegex(ExternalAnchorError,'SIGNATURE_MISMATCH'):self.anchor.verify()
    def test_tampered_state(self):
        self.anchor.checkpoint();self.rbac.db.execute('UPDATE ldaps_rbac_directory_freshness SET max_age_seconds=999')
        with self.assertRaisesRegex(ExternalAnchorError,'STATE_MISMATCH'):self.anchor.verify()
    def test_policy_head_drift(self):
        self.anchor.checkpoint();self.audit['last_hash']='b'*64
        with self.assertRaisesRegex(ExternalAnchorError,'STATE_MISMATCH'):self.anchor.verify()
    def test_missing_policy(self):
        self.audit['events']=0
        with self.assertRaisesRegex(ExternalAnchorError,'AUDITED_POLICY_REQUIRED'):self.anchor.checkpoint()
    def test_wrong_key(self):
        self.anchor.checkpoint();other=ExternalPolicyAnchor(self.rbac,anchor_path=self.anchor.path,key=b'y'*32)
        with self.assertRaisesRegex(ExternalAnchorError,'SIGNATURE_MISMATCH'):other.verify()
    def test_strict_mode_drift(self):
        self.anchor.checkpoint();self.rbac.db.execute('CREATE TABLE ldaps_strict_security (id INTEGER PRIMARY KEY,enabled INTEGER,enabled_at INTEGER)');self.rbac.db.execute('INSERT INTO ldaps_strict_security VALUES(1,1,101)')
        with self.assertRaisesRegex(ExternalAnchorError,'STATE_MISMATCH'):self.anchor.verify()
    def test_permissions(self):
        self.anchor.checkpoint();self.assertEqual(self.anchor.path.stat().st_mode&0o777,0o600)
    def test_malformed(self):
        self.anchor.path.write_text('{}')
        with self.assertRaisesRegex(ExternalAnchorError,'FORMAT_INVALID'):self.anchor.verify()

if __name__=='__main__':unittest.main()
