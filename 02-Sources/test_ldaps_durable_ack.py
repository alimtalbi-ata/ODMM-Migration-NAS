import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from ldaps_policy_transition import SupervisedPolicyTransition
from ldaps_transition_reconciliation import TransitionReconciler,TransitionReconciliationError
from ldaps_durable_ack import DurableAcknowledgement

class DurableAckTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        p=Path(tmp.name);self.db=sqlite3.connect(p/'audit.db');self.addCleanup(self.db.close)
        self.t=SupervisedPolicyTransition(Mock(),anchor_path=p/'anchor',key=b'x'*32,intent_path=p/'intent')
        self.r=TransitionReconciler(self.t,lock_path=p/'lock')
        self.a=DurableAcknowledgement(self.r,self.db)
        self.intent={'version':1,'previous_head':'old','new_limit':10,'requested_at':5}
        self.t._write(self.intent)
        self.p=patch.object(self.t,'inspect',return_value={'status':'PUBLISHED_AWAITING_OPERATOR_ACK'});self.p.start();self.addCleanup(self.p.stop)
        self.e=self.r.inspect(now=10,max_age_seconds=20)
    def test_success(self):
        with patch.object(self.t,'acknowledge',return_value={'status':'TRANSITION_ACKNOWLEDGED'}):
            self.assertEqual(self.a.acknowledge(self.e,operator_confirmed=True,now=10,max_age_seconds=20)['status'],'TRANSITION_ACKNOWLEDGED')
        self.assertEqual(self.a.verify()['count'],1)
    def test_replay(self):
        with patch.object(self.t,'acknowledge',return_value={}):self.a.acknowledge(self.e,operator_confirmed=True,now=10,max_age_seconds=20)
        with self.assertRaisesRegex(TransitionReconciliationError,'ACK_REPLAY_BLOCKED'):
            self.a.acknowledge(self.e,operator_confirmed=True,now=10,max_age_seconds=20)
    def test_no_confirmation(self):
        with self.assertRaises(TransitionReconciliationError):self.a.acknowledge(self.e,operator_confirmed=False,now=10,max_age_seconds=20)
    def test_stale(self):
        with self.assertRaises(TransitionReconciliationError):self.a.acknowledge(self.e,operator_confirmed=True,now=40,max_age_seconds=20)
    def test_future(self):
        with self.assertRaises(TransitionReconciliationError):self.a.acknowledge(self.e,operator_confirmed=True,now=9,max_age_seconds=20)
    def test_tamper_evidence(self):
        self.e['status']='X'
        with self.assertRaises(TransitionReconciliationError):self.a.acknowledge(self.e,operator_confirmed=True,now=10,max_age_seconds=20)
    def test_changed_intent(self):
        self.t._write({**self.intent,'new_limit':20})
        with self.assertRaises(TransitionReconciliationError):self.a.acknowledge(self.e,operator_confirmed=True,now=10,max_age_seconds=20)
    def test_not_ready(self):
        with patch.object(self.t,'inspect',return_value={'status':'SQLITE_COMMITTED_ANCHOR_UNCERTAIN'}):
            with self.assertRaises(TransitionReconciliationError):self.a.acknowledge(self.e,operator_confirmed=True,now=10,max_age_seconds=20)
    def test_interrupted_unlink(self):
        with patch.object(self.t,'acknowledge',side_effect=OSError('unlink failed')):
            with self.assertRaises(OSError):self.a.acknowledge(self.e,operator_confirmed=True,now=10,max_age_seconds=20)
        self.assertEqual(self.a.inspect_interruption()['status'],'RECEIPT_COMMITTED_INTENT_PRESENT_MANUAL_RECOVERY')
    def test_integrity(self):
        with patch.object(self.t,'acknowledge',return_value={}):self.a.acknowledge(self.e,operator_confirmed=True,now=10,max_age_seconds=20)
        self.db.execute("UPDATE transition_ack_receipts SET acknowledged_at=11")
        with self.assertRaisesRegex(TransitionReconciliationError,'ACK_LEDGER_TAMPERED'):self.a.verify()
    def test_rollback(self):
        self.db.execute('''CREATE TRIGGER deny_ack BEFORE INSERT ON transition_ack_receipts BEGIN SELECT RAISE(ABORT,'denied'); END''')
        with self.assertRaises(sqlite3.DatabaseError):self.a.acknowledge(self.e,operator_confirmed=True,now=10,max_age_seconds=20)
        self.assertEqual(self.a.verify()['count'],0)
    def test_no_receipt(self):self.assertEqual(self.a.inspect_interruption()['status'],'NO_RECEIPT_FOR_INTENT')
    def test_restart(self):
        with patch.object(self.t,'acknowledge',side_effect=OSError('crash')):
            with self.assertRaises(OSError):self.a.acknowledge(self.e,operator_confirmed=True,now=10,max_age_seconds=20)
        self.db.close();self.db=sqlite3.connect(self.r.lock_path.parent/'audit.db')
        other=DurableAcknowledgement(self.r,self.db)
        self.assertEqual(other.verify()['count'],1)
if __name__=='__main__':unittest.main()
