import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from ldaps_ipc_persistent_identity import PersistentProcessIdentity, IdentityPinError
from ldaps_ipc_dual_pin import DualPinController
from ldaps_ipc_authenticated_rotation import AuthenticatedPinRotation

class AuthenticatedRotationTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);root=Path(t.name)
        self.guard=Mock(digest='a'*64)
        self.guard.check.return_value={'status':'PEER_PROCESS_VERIFIED','peer_pid':11,'process_start_ticks':22}
        self.pin=PersistentProcessIdentity(self.guard,pin_path=root/'pin',key=b'p'*32)
        self.pin.enroll(operator_confirmed=True,expected_pid=11,expected_start_ticks=22)
        self.ctrl=DualPinController(self.pin,gate_path=root/'gate.db',key=b'g'*32)
        self.verifier=Mock()
        self.verifier.assert_role=Mock()
        self.verifier.verify.side_effect=lambda token,now: {'subject':token,'token_id':token+'-jti','issuer':'https://issuer','verified':True}
        self.facade=AuthenticatedPinRotation(self.ctrl,self.verifier,checkpoint_path=root/'anchor',checkpoint_key=b'c'*32)
        self.facade.enroll_checkpoint(operator_confirmed=True)
    def change(self):
        self.guard.check.return_value={'status':'PEER_PROCESS_VERIFIED','peer_pid':33,'process_start_ticks':44}
    def rotate(self,**kwargs):
        args={'security_token':'alice','operations_token':'bob','now':123,'expected_pid':33,'expected_start_ticks':44,'operator_confirmed':True}
        args.update(kwargs)
        return self.facade.rotate(**args)
    def test_initial_checkpoint(self):self.assertEqual(self.facade.inspect()['status'],'CHECKPOINT_VERIFIED')
    def test_valid_rotation(self):
        self.change();self.assertEqual(self.rotate()['status'],'AUTHENTICATED_PIN_ROTATED');self.assertEqual(self.facade.inspect()['status'],'CHECKPOINT_VERIFIED')
        self.verifier.assert_role.assert_any_call({'subject':'alice','token_id':'alice-jti','issuer':'https://issuer','verified':True},'SECURITY')
    def test_same_identity(self):
        self.change()
        with self.assertRaisesRegex(IdentityPinError,'REVIEWER_SEPARATION_REQUIRED'):self.rotate(operations_token='alice')
    def test_no_confirmation(self):
        with self.assertRaises(IdentityPinError):self.rotate(operator_confirmed=False)
    def test_no_role_authority(self):
        self.change();del self.verifier.assert_role
        with self.assertRaises(IdentityPinError):self.rotate()
    def test_role_denied(self):
        self.change();self.verifier.assert_role.side_effect=IdentityPinError('ROLE_DENIED')
        with self.assertRaisesRegex(IdentityPinError,'ROLE_DENIED'):self.rotate()
        self.assertEqual(self.facade.inspect()['status'],'CHECKPOINT_VERIFIED')
    def test_invalid_jwt(self):
        self.change();self.verifier.verify.side_effect=ValueError('invalid signature')
        with self.assertRaises(ValueError):self.rotate()
    def test_audit_rollback_detected(self):
        self.change();self.rotate()
        with sqlite3.connect(self.ctrl.gate_path) as db:db.execute('DELETE FROM pin_audit')
        self.assertEqual(self.facade.inspect()['status'],'AUDIT_CHECKPOINT_MISMATCH_MANUAL_REVIEW')
    def test_pin_rollback_detected(self):
        original=self.pin.path.read_bytes();self.change();self.rotate();self.pin.path.write_bytes(original)
        self.assertEqual(self.facade.inspect()['status'],'PIN_CHECKPOINT_MISMATCH_MANUAL_REVIEW')
    def test_anchor_tamper(self):
        self.facade.path.write_text('{}');self.assertEqual(self.facade.inspect()['status'],'EVIDENCE_INVALID_MANUAL_REVIEW')
    def test_anchor_missing(self):
        self.facade.path.unlink();self.assertEqual(self.facade.inspect()['status'],'CHECKPOINT_MISSING_MANUAL_REVIEW')
    def test_anchor_reenroll_forbidden(self):
        with self.assertRaisesRegex(IdentityPinError,'CHECKPOINT_ALREADY_EXISTS'):self.facade.enroll_checkpoint(operator_confirmed=True)
    def test_reopen(self):
        other=AuthenticatedPinRotation(self.ctrl,self.verifier,checkpoint_path=self.facade.path,checkpoint_key=b'c'*32)
        self.assertEqual(other.inspect()['status'],'CHECKPOINT_VERIFIED')
    def test_wrong_key(self):
        other=AuthenticatedPinRotation(self.ctrl,self.verifier,checkpoint_path=self.facade.path,checkpoint_key=b'x'*32)
        self.assertEqual(other.inspect()['status'],'EVIDENCE_INVALID_MANUAL_REVIEW')
    def test_crash_after_audit(self):
        self.change();self.facade._write=Mock(side_effect=OSError('disk full'))
        with self.assertRaises(OSError):self.rotate()
        self.assertEqual(self.facade.inspect()['status'],'AUDIT_CHECKPOINT_MISMATCH_MANUAL_REVIEW')
    def test_invalid_time(self):
        with self.assertRaises(IdentityPinError):self.rotate(now=-1)
