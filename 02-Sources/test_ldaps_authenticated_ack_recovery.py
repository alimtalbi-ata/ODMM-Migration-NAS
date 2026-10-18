import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from ldaps_policy_transition import SupervisedPolicyTransition
from ldaps_transition_reconciliation import TransitionReconciler,TransitionReconciliationError
from ldaps_durable_ack import DurableAcknowledgement
from ldaps_ack_recovery import InterruptedAckRecovery
from ldaps_authenticated_ack_recovery import AuthenticatedAckRecovery

class AuthenticatedRecoveryTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        p=Path(t.name)
        self.db=sqlite3.connect(p/'db.sqlite');self.addCleanup(self.db.close)
        self.transition=SupervisedPolicyTransition(Mock(),anchor_path=p/'anchor',key=b'x'*32,intent_path=p/'intent')
        self.reconciler=TransitionReconciler(self.transition,lock_path=p/'lock')
        self.ack=DurableAcknowledgement(self.reconciler,self.db)
        self.recovery=InterruptedAckRecovery(self.ack)
        self.transition._write({'version':1,'previous_head':'old','new_limit':10,'requested_at':5})
        self.patcher=patch.object(self.transition,'inspect',return_value={'status':'PUBLISHED_AWAITING_OPERATOR_ACK'})
        self.patcher.start();self.addCleanup(self.patcher.stop)
        evidence=self.reconciler.inspect(now=10,max_age_seconds=20)
        with patch.object(self.transition,'acknowledge',side_effect=OSError('crash')):
            with self.assertRaises(OSError):self.ack.acknowledge(evidence,operator_confirmed=True,now=10,max_age_seconds=20)
        self.service=AuthenticatedAckRecovery(self.recovery,issuer_keys={'issuer':b'k'*32},grants={'sec-b':'SECURITY','ops-a':'OPERATIONS'})
    def token(self,**overrides):
        args=dict(issuer='issuer',subject='sec-b',role='SECURITY',token_id='t1',issued_at=10,expires_at=30)
        args.update(overrides)
        return self.service.sign(b'k'*32,**args)
    def recover(self,token=None,**overrides):
        args=dict(token=self.token() if token is None else token,original_operator='ops-a',operator_confirmed=True,now=11,max_age_seconds=20)
        args.update(overrides)
        return self.service.recover(**args)
    def test_success(self):
        self.assertEqual(self.recover()['status'],'TRANSITION_ACKNOWLEDGED')
        self.assertEqual(self.service.verify()['count'],1)
    def test_signature_tamper(self):
        token=self.token();token['subject']='ops-a'
        with self.assertRaisesRegex(TransitionReconciliationError,'INVALID_IDENTITY_SIGNATURE'):self.recover(token)
    def test_expired(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'EXPIRED_IDENTITY_TOKEN'):self.recover(self.token(expires_at=11))
    def test_future(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'EXPIRED_IDENTITY_TOKEN'):self.recover(self.token(issued_at=12))
    def test_wrong_role(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'RECOVERY_SECURITY_ROLE_REQUIRED'):self.recover(self.token(subject='ops-a',role='OPERATIONS'))
    def test_same_operator(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'INDEPENDENT_REVIEWER_REQUIRED'):self.recover(original_operator='sec-b')
    def test_missing_confirmation(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED'):self.recover(operator_confirmed=False)
    def test_wrong_key(self):
        token=self.service.sign(b'z'*32,issuer='issuer',subject='sec-b',role='SECURITY',token_id='t1',issued_at=10,expires_at=30)
        with self.assertRaisesRegex(TransitionReconciliationError,'INVALID_IDENTITY_SIGNATURE'):self.recover(token)
    def test_stale_receipt(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'STALE_RECEIPT'):self.recover(now=40,token=self.token(expires_at=50))
    def test_unlink_failure_no_replay(self):
        with patch.object(self.transition,'acknowledge',side_effect=OSError('crash')):
            with self.assertRaises(OSError):self.recover()
        self.assertEqual(self.service.verify()['count'],1)
        with self.assertRaisesRegex(TransitionReconciliationError,'RECOVERY_NOT_READY'):self.recover()
    def test_audit_tamper(self):
        self.recover()
        self.db.execute("UPDATE authenticated_ack_reviews SET reviewer='evil'");self.db.commit()
        with self.assertRaisesRegex(TransitionReconciliationError,'AUTHENTICATED_REVIEW_AUDIT_TAMPERED'):self.service.verify()
    def test_insert_rollback(self):
        self.db.execute("CREATE TRIGGER reject_auth BEFORE INSERT ON authenticated_ack_reviews BEGIN SELECT RAISE(ABORT,'blocked'); END");self.db.commit()
        with self.assertRaises(sqlite3.DatabaseError):self.recover()
        self.assertTrue(self.transition.intent.exists())
        self.assertEqual(self.service.verify()['count'],0)
    def test_unknown_issuer(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'UNTRUSTED_IDENTITY_ISSUER'):self.recover(self.token(issuer='other'))

if __name__=='__main__':unittest.main()
