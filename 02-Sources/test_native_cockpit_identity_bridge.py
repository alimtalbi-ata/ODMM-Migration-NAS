import tempfile
import unittest
from pathlib import Path
from native_cockpit_identity_bridge import server_principal, verify_external_anchor
from native_benchmark_cockpit_adapter import _audit
from native_cockpit_audit_operations import verify_access_audit

class IdentityBridgeTests(unittest.TestCase):
    def setUp(self):
        self.claims={'server_verified':True,'iss':'issuer','aud':'odmm','sub':'operator',
                     'groups':['odmm:evidence:read']}
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'audit.sqlite';self.key=b'K'*32
    def test_valid_mapping(self):
        self.assertEqual(server_principal(self.claims,expected_issuer='issuer',expected_audience='odmm')['roles'],['evidence_viewer'])
    def test_unverified_denied(self):
        with self.assertRaises(PermissionError):server_principal({**self.claims,'server_verified':False},expected_issuer='issuer',expected_audience='odmm')
    def test_issuer_denied(self):
        with self.assertRaises(PermissionError):server_principal(self.claims,expected_issuer='other',expected_audience='odmm')
    def test_audience_denied(self):
        with self.assertRaises(PermissionError):server_principal(self.claims,expected_issuer='issuer',expected_audience='other')
    def test_groups_denied(self):
        with self.assertRaises(PermissionError):server_principal({**self.claims,'groups':['unknown']},expected_issuer='issuer',expected_audience='odmm')
    def test_anchor_exact(self):
        _audit(self.db,'operator','read','ALLOW','digest',self.key)
        anchor=verify_access_audit(self.db,audit_key=self.key)
        self.assertEqual(verify_external_anchor(self.db,anchor,audit_key=self.key)['count'],1)
    def test_anchor_tampered(self):
        _audit(self.db,'operator','read','ALLOW','digest',self.key)
        anchor=verify_access_audit(self.db,audit_key=self.key)
        with self.assertRaises(ValueError):verify_external_anchor(self.db,{**anchor,'head_sha256':'a'*64},audit_key=self.key)
    def test_anchor_historical_prefix_accepted(self):
        _audit(self.db,'operator','read','ALLOW','digest',self.key)
        anchor=verify_access_audit(self.db,audit_key=self.key)
        _audit(self.db,'operator','read','ALLOW','digest',self.key)
        self.assertEqual(verify_external_anchor(self.db,anchor,audit_key=self.key)['count'],2)
    def test_anchor_wrong_key(self):
        _audit(self.db,'operator','read','ALLOW','digest',self.key)
        anchor=verify_access_audit(self.db,audit_key=self.key)
        with self.assertRaises(ValueError):verify_external_anchor(self.db,anchor,audit_key=b'X'*32)
