import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from ldaps_policy_transition import SupervisedPolicyTransition
from ldaps_transition_reconciliation import TransitionReconciler,TransitionReconciliationError
from ldaps_durable_ack import DurableAcknowledgement
from ldaps_ack_recovery import InterruptedAckRecovery

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        p=Path(t.name)
        self.db=sqlite3.connect(p/'audit.db');self.addCleanup(lambda: self.db.close())
        self.transition=SupervisedPolicyTransition(Mock(),anchor_path=p/'anchor',key=b'x'*32,intent_path=p/'intent')
        self.reconciler=TransitionReconciler(self.transition,lock_path=p/'lock')
        self.ack=DurableAcknowledgement(self.reconciler,self.db)
        self.recovery=InterruptedAckRecovery(self.ack)
        self.transition._write({'version':1,'previous_head':'old','new_limit':10,'requested_at':5})
        self.patch=patch.object(self.transition,'inspect',return_value={'status':'PUBLISHED_AWAITING_OPERATOR_ACK'})
        self.patch.start();self.addCleanup(self.patch.stop)
        evidence=self.reconciler.inspect(now=10,max_age_seconds=20)
        with patch.object(self.transition,'acknowledge',side_effect=OSError('crash')):
            with self.assertRaises(OSError):self.ack.acknowledge(evidence,operator_confirmed=True,now=10,max_age_seconds=20)
    def recover(self,**kw):
        args={'reviewer':'security-b','original_operator':'operations-a','operator_confirmed':True,'now':11,'max_age_seconds':20}
        args.update(kw)
        return self.recovery.recover(**args)
    def test_inspect(self):self.assertEqual(self.recovery.inspect()['status'],'RECOVERABLE_WITH_INDEPENDENT_REVIEW')
    def test_success(self):
        self.assertEqual(self.recover()['status'],'TRANSITION_ACKNOWLEDGED')
        self.assertFalse(self.transition.intent.exists())
        self.assertEqual(self.recovery.verify()['count'],1)
    def test_same_reviewer(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'INDEPENDENT_REVIEWER_REQUIRED'):self.recover(reviewer='operations-a')
    def test_missing_confirmation(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'EXPLICIT_OPERATOR_CONFIRMATION_REQUIRED'):self.recover(operator_confirmed=False)
    def test_stale(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'STALE_RECEIPT'):self.recover(now=50)
    def test_future(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'STALE_RECEIPT'):self.recover(now=9)
    def test_policy_changed(self):
        with patch.object(self.transition,'inspect',return_value={'status':'SQLITE_COMMITTED_ANCHOR_UNCERTAIN'}):
            with self.assertRaisesRegex(TransitionReconciliationError,'POLICY_NOT_VERIFIED'):self.recover()
    def test_receipt_missing(self):
        self.db.execute('DELETE FROM transition_ack_receipts');self.db.commit()
        with self.assertRaisesRegex(TransitionReconciliationError,'DURABLE_RECEIPT_REQUIRED'):self.recover()
    def test_replay_after_unlink_failure(self):
        with patch.object(self.transition,'acknowledge',side_effect=OSError('unlink')):
            with self.assertRaises(OSError):self.recover()
        self.assertEqual(self.recovery.inspect()['status'],'RECOVERY_RECORDED_INTENT_PRESENT_MANUAL_INVESTIGATION')
        with self.assertRaisesRegex(TransitionReconciliationError,'RECOVERY_REPLAY_BLOCKED'):self.recover()
    def test_audit_tamper(self):
        self.recover()
        self.db.execute('UPDATE ack_recovery_events SET reviewer=?',('evil',));self.db.commit()
        with self.assertRaisesRegex(TransitionReconciliationError,'RECOVERY_AUDIT_TAMPERED'):self.recovery.verify()
    def test_insert_rollback(self):
        self.db.execute("CREATE TRIGGER deny_recovery BEFORE INSERT ON ack_recovery_events BEGIN SELECT RAISE(ABORT,'blocked'); END")
        self.db.commit()
        with self.assertRaises(sqlite3.DatabaseError):self.recover()
        self.assertTrue(self.transition.intent.exists())
        self.assertEqual(self.recovery.verify()['count'],0)
    def test_restart(self):
        with patch.object(self.transition,'acknowledge',side_effect=OSError('unlink')):
            with self.assertRaises(OSError):self.recover()
        self.db.close();self.db=sqlite3.connect(self.reconciler.lock_path.parent/'audit.db')
        reopened=InterruptedAckRecovery(DurableAcknowledgement(self.reconciler,self.db))
        self.assertEqual(reopened.verify()['count'],1)
    def test_no_intent(self):
        self.transition.intent.unlink()
        self.assertEqual(self.recovery.inspect()['status'],'NO_PENDING_INTENT')
if __name__=='__main__':unittest.main()
