import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from ldaps_ipc_persistent_identity import PersistentProcessIdentity, IdentityPinError
from ldaps_ipc_dual_pin import DualPinController
from ldaps_ipc_authenticated_rotation import AuthenticatedPinRotation
from ldaps_ipc_serialized_rotation import SerializedAuthenticatedRotation
from ldaps_ipc_reconciliation import SupervisedRotationReconciliation

class ReconciliationTests(unittest.TestCase):
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
        serialized=SerializedAuthenticatedRotation(facade,lock_path=root/'lock.db')
        serialized.enroll_checkpoint(operator_confirmed=True)
        self.guard=guard;self.facade=facade;self.verifier=verifier
        self.recon=SupervisedRotationReconciliation(serialized,receipt_key=b'r'*32)
        self.serialized=serialized
    def interrupt(self):
        self.facade.path.unlink()
    def review(self,**kwargs):
        return self.recon.review(security_token='alice',operations_token='bob',now=100,
            expected_evidence_sha256=self.recon.report()['evidence_sha256'],operator_confirmed=True,**kwargs)
    def test_healthy_report(self):
        self.assertFalse(self.recon.report()['manual_review_required'])
    def test_healthy_review_refused(self):
        with self.assertRaisesRegex(IdentityPinError,'NO_INTERRUPTED_ROTATION'):self.review()
    def test_missing_checkpoint_report(self):
        self.interrupt();self.assertTrue(self.recon.report()['manual_review_required'])
    def test_review_receipt(self):
        self.interrupt();result=self.review();self.assertEqual(result['status'],'REVIEW_RECEIPT_ISSUED')
        self.assertFalse(result['cutover_authorized'])
        self.assertEqual(self.recon.verify_receipt(result)['status'],'RECEIPT_SIGNATURE_VERIFIED')
    def test_no_repair(self):
        self.interrupt();self.review();self.assertFalse(self.facade.path.exists())
    def test_no_confirmation(self):
        self.interrupt()
        with self.assertRaisesRegex(IdentityPinError,'EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED'):
            self.recon.review(security_token='alice',operations_token='bob',now=100,
                expected_evidence_sha256=self.recon.report()['evidence_sha256'],operator_confirmed=False)
    def test_same_reviewer(self):
        self.interrupt()
        with self.assertRaisesRegex(IdentityPinError,'REVIEWER_SEPARATION_REQUIRED'):
            self.recon.review(security_token='alice',operations_token='alice',now=100,
                expected_evidence_sha256=self.recon.report()['evidence_sha256'],operator_confirmed=True)
    def test_stale_evidence(self):
        before=self.recon.report()['evidence_sha256'];self.interrupt()
        with self.assertRaisesRegex(IdentityPinError,'EVIDENCE_CHANGED_MANUAL_REVIEW'):
            self.recon.review(security_token='alice',operations_token='bob',now=100,
                expected_evidence_sha256=before,operator_confirmed=True)
    def test_tampered_receipt(self):
        self.interrupt();receipt=self.review();receipt['receipt']['security_subject']='mallory'
        with self.assertRaisesRegex(IdentityPinError,'REVIEW_RECEIPT_INVALID'):self.recon.verify_receipt(receipt)
    def test_wrong_key(self):
        self.interrupt();receipt=self.review()
        other=SupervisedRotationReconciliation(self.serialized,receipt_key=b'x'*32)
        with self.assertRaisesRegex(IdentityPinError,'REVIEW_RECEIPT_INVALID'):other.verify_receipt(receipt)
    def test_bad_key(self):
        with self.assertRaisesRegex(IdentityPinError,'RECONCILIATION_KEY_TOO_SHORT'):
            SupervisedRotationReconciliation(self.serialized,receipt_key=b'x')
    def test_invalid_time(self):
        self.interrupt()
        with self.assertRaisesRegex(IdentityPinError,'INVALID_TIME'):
            self.recon.review(security_token='alice',operations_token='bob',now=-1,
                expected_evidence_sha256=self.recon.report()['evidence_sha256'],operator_confirmed=True)
    def test_role_failure(self):
        self.interrupt();self.verifier.assert_role.side_effect=IdentityPinError('ROLE_DENIED')
        with self.assertRaisesRegex(IdentityPinError,'ROLE_DENIED'):self.review()
