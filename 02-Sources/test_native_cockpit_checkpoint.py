import tempfile
import unittest
from pathlib import Path
from native_benchmark_cockpit_adapter import _audit
from native_cockpit_audit_operations import verify_access_audit, verify_access_audit_prefix
from native_cockpit_identity_bridge import verify_external_anchor

class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'audit.sqlite'; self.key=b'K'*32
        _audit(self.db,'user','read','ALLOW','digest',self.key)
        self.anchor=verify_access_audit(self.db,audit_key=self.key)
    def append(self):
        return _audit(self.db,'user','read','ALLOW','digest',self.key)
    def test_historical_checkpoint(self):
        self.append(); self.append()
        self.assertEqual(verify_external_anchor(self.db,self.anchor,audit_key=self.key)['count'],3)
    def test_append_under_historical_checkpoint(self):
        self.append()
        _audit(self.db,'user','read','ALLOW','digest',self.key,
               trusted_audit_head=self.anchor['head_sha256'],trusted_checkpoint_count=1)
        self.assertEqual(verify_access_audit(self.db,audit_key=self.key)['count'],3)
    def test_prefix_tampering(self):
        self.append()
        with self.assertRaisesRegex(ValueError,'AUDIT_CHECKPOINT_MISMATCH'):
            verify_access_audit_prefix(self.db,audit_key=self.key,checkpoint_count=1,checkpoint_head='f'*64)
    def test_append_wrong_checkpoint_no_mutation(self):
        before=verify_access_audit(self.db,audit_key=self.key)
        with self.assertRaisesRegex(ValueError,'AUDIT_CHECKPOINT_MISMATCH'):
            _audit(self.db,'user','read','ALLOW','digest',self.key,
                   trusted_audit_head='f'*64,trusted_checkpoint_count=1)
        self.assertEqual(verify_access_audit(self.db,audit_key=self.key),before)
    def test_rollback_detected(self):
        with self.assertRaisesRegex(ValueError,'AUDIT_ROLLBACK_DETECTED'):
            verify_access_audit_prefix(self.db,audit_key=self.key,checkpoint_count=5,checkpoint_head='f'*64)
    def test_empty_checkpoint(self):
        genesis='0'*64
        self.assertTrue(verify_access_audit_prefix(self.db,audit_key=self.key,checkpoint_count=0,checkpoint_head=genesis)['checkpoint_verified'])
    def test_invalid_checkpoint(self):
        with self.assertRaises(ValueError):
            verify_access_audit_prefix(self.db,audit_key=self.key,checkpoint_count=True,checkpoint_head='0'*64)
