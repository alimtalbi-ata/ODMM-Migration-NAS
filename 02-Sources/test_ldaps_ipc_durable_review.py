import sqlite3
import unittest
import tempfile
from unittest.mock import Mock
from ldaps_ipc_persistent_identity import PersistentProcessIdentity
from ldaps_ipc_dual_pin import DualPinController
from ldaps_ipc_authenticated_rotation import AuthenticatedPinRotation
from ldaps_ipc_serialized_rotation import SerializedAuthenticatedRotation
from ldaps_ipc_reconciliation import SupervisedRotationReconciliation
from pathlib import Path
from ldaps_ipc_durable_review import DurableIPCReview
from ldaps_ipc_persistent_identity import IdentityPinError

class DurableReviewTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        guard=Mock(digest='a'*64)
        guard.check.return_value={'status':'PEER_PROCESS_VERIFIED','peer_pid':11,'process_start_ticks':22}
        pin=PersistentProcessIdentity(guard,pin_path=root/'pin',key=b'p'*32)
        pin.enroll(operator_confirmed=True,expected_pid=11,expected_start_ticks=22)
        controller=DualPinController(pin,gate_path=root/'gate.db',key=b'g'*32)
        verifier=Mock()
        verifier.verify.side_effect=lambda token,now:{'subject':token,'token_id':token+'-id','issuer':'issuer'}
        verifier.assert_role=Mock()
        facade=AuthenticatedPinRotation(controller,verifier,checkpoint_path=root/'anchor',checkpoint_key=b'c'*32)
        self.serialized=SerializedAuthenticatedRotation(facade,lock_path=root/'lock.db')
        self.serialized.enroll_checkpoint(operator_confirmed=True)
        self.facade=facade
        self.recon=SupervisedRotationReconciliation(self.serialized,receipt_key=b'r'*32)
        self.interrupt()
        self.path = self.serialized.lock_path.parent / 'reviews.db'
        self.store = DurableIPCReview(self.recon, journal_path=self.path, key=b'd'*32)
    def interrupt(self):
        self.facade.path.unlink()
    def archive(self):
        return self.store.review(security_token='alice', operations_token='bob',now=100,
            expected_evidence_sha256=self.recon.report()['evidence_sha256'],operator_confirmed=True)
    def test_archive(self):
        result=self.archive();self.assertEqual(result['sequence'],1)
        self.assertFalse(result['cutover_authorized'])
    def test_verify(self):
        self.archive();self.assertEqual(self.store.verify()['count'],1)
    def test_restart(self):
        self.archive();again=DurableIPCReview(self.recon,journal_path=self.path,key=b'd'*32)
        self.assertEqual(again.verify()['count'],1)
    def test_replay(self):
        self.archive()
        with self.assertRaisesRegex(IdentityPinError,'ALREADY_ARCHIVED'):self.archive()
    def test_tamper(self):
        self.archive()
        with sqlite3.connect(self.path) as db:db.execute("UPDATE ipc_review_receipts SET payload='{}'")
        with self.assertRaises(IdentityPinError):self.store.verify()
    def test_wrong_key(self):
        self.archive()
        with self.assertRaises(IdentityPinError):DurableIPCReview(self.recon,journal_path=self.path,key=b'x'*32).verify()
    def test_invalid_key(self):
        with self.assertRaises(IdentityPinError):DurableIPCReview(self.recon,journal_path=self.path,key=b'x')
    def test_invalid_path(self):
        with self.assertRaises(IdentityPinError):DurableIPCReview(self.recon,journal_path=self.serialized.lock_path,key=b'd'*32)
    def test_no_confirmation_no_entry(self):
        with self.assertRaises(IdentityPinError):self.store.review(security_token='alice',operations_token='bob',now=100,expected_evidence_sha256=self.recon.report()['evidence_sha256'],operator_confirmed=False)
        self.assertEqual(self.store.verify()['count'],0)
    def test_stale_evidence_no_entry(self):
        with self.assertRaises(IdentityPinError):self.store.review(security_token='alice',operations_token='bob',now=100,expected_evidence_sha256='f'*64,operator_confirmed=True)
        self.assertEqual(self.store.verify()['count'],0)
    def test_no_repair(self):
        self.archive();self.assertFalse(self.facade.path.exists())
