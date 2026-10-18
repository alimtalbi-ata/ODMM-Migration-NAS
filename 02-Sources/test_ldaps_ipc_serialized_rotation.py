import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from ldaps_ipc_persistent_identity import PersistentProcessIdentity, IdentityPinError
from ldaps_ipc_dual_pin import DualPinController
from ldaps_ipc_authenticated_rotation import AuthenticatedPinRotation
from ldaps_ipc_serialized_rotation import SerializedAuthenticatedRotation

class SerializedRotationTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        self.guard=Mock(digest='a'*64)
        self.guard.check.return_value={'status':'PEER_PROCESS_VERIFIED','peer_pid':11,'process_start_ticks':22}
        self.pin=PersistentProcessIdentity(self.guard,pin_path=root/'pin',key=b'p'*32)
        self.pin.enroll(operator_confirmed=True,expected_pid=11,expected_start_ticks=22)
        self.controller=DualPinController(self.pin,gate_path=root/'gate.db',key=b'g'*32)
        self.verifier=Mock()
        self.verifier.assert_role=Mock()
        self.verifier.verify.side_effect=lambda token,now:{'subject':token,'token_id':token+'-id','issuer':'issuer'}
        self.facade=AuthenticatedPinRotation(self.controller,self.verifier,checkpoint_path=root/'anchor',checkpoint_key=b'c'*32)
        self.lock=root/'lock.db'
        self.service=SerializedAuthenticatedRotation(self.facade,lock_path=self.lock)
        self.service.enroll_checkpoint(operator_confirmed=True)
    def test_verified(self):
        self.assertEqual(self.service.inspect()['status'],'CHECKPOINT_VERIFIED')
    def test_report_read_only(self):
        self.assertEqual(self.service.reconciliation_report()['automatic_repair_authorized'],False)
    def test_rotate(self):
        self.guard.check.return_value={'status':'PEER_PROCESS_VERIFIED','peer_pid':33,'process_start_ticks':44}
        result=self.service.rotate(security_token='alice',operations_token='bob',now=100,expected_pid=33,expected_start_ticks=44,operator_confirmed=True)
        self.assertEqual(result['status'],'AUTHENTICATED_PIN_ROTATED')
        self.assertEqual(self.service.inspect()['status'],'CHECKPOINT_VERIFIED')
    def test_lock_contention(self):
        db=sqlite3.connect(self.lock,isolation_level=None)
        db.execute('BEGIN IMMEDIATE')
        try:
            with self.assertRaisesRegex(IdentityPinError,'ROTATION_LOCK_BUSY'):self.service.inspect()
        finally:db.execute('ROLLBACK');db.close()
    def test_lock_released_after_exception(self):
        with self.assertRaisesRegex(IdentityPinError,'EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED'):
            self.service.rotate(security_token='alice',operations_token='bob',now=100,expected_pid=33,expected_start_ticks=44,operator_confirmed=False)
        self.assertEqual(self.service.inspect()['status'],'CHECKPOINT_VERIFIED')
    def test_reopen(self):
        again=SerializedAuthenticatedRotation(self.facade,lock_path=self.lock)
        self.assertEqual(again.inspect()['status'],'CHECKPOINT_VERIFIED')
    def test_symlink_forbidden(self):
        alias=self.lock.parent/'alias';alias.symlink_to(self.lock)
        with self.assertRaisesRegex(IdentityPinError,'ROTATION_LOCK_SYMLINK_FORBIDDEN'):
            SerializedAuthenticatedRotation(self.facade,lock_path=alias)
    def test_collision(self):
        with self.assertRaisesRegex(IdentityPinError,'ROTATION_LOCK_PATH_COLLISION'):
            SerializedAuthenticatedRotation(self.facade,lock_path=self.facade.path)
    def test_checkpoint_mismatch_blocks(self):
        self.facade.path.write_text('{}')
        self.assertEqual(self.service.reconciliation_report()['status'],'EVIDENCE_INVALID_MANUAL_REVIEW')
        with self.assertRaisesRegex(IdentityPinError,'ROTATION_RECONCILIATION_REQUIRED'):
            self.service.rotate(operator_confirmed=True)
    def test_missing_checkpoint_blocks(self):
        self.facade.path.unlink()
        self.assertTrue(self.service.reconciliation_report()['manual_review_required'])
    def test_no_cutover(self):
        self.assertFalse(self.service.reconciliation_report()['cutover_authorized'])
