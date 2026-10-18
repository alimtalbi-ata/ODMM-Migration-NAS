import fcntl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
from ldaps_policy_transition import SupervisedPolicyTransition
from ldaps_transition_reconciliation import TransitionReconciler,TransitionReconciliationError

class Tests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        root=Path(t.name)
        self.t=SupervisedPolicyTransition(Mock(),anchor_path=root/'anchor',key=b'x'*32,intent_path=root/'intent')
        self.r=TransitionReconciler(self.t,lock_path=root/'lock')
        self.intent={'version':1,'previous_head':'old','new_limit':10,'requested_at':5}
    def test_no_pending(self):self.assertEqual(self.r.inspect(now=10,max_age_seconds=20)['status'],'NO_PENDING_TRANSITION')
    def test_intent_only(self):
        self.t._write(self.intent)
        with patch.object(self.t,'inspect',return_value={'status':'INTENT_ONLY_MANUAL_REVIEW'}):
            self.assertEqual(self.r.inspect(now=10,max_age_seconds=20)['status'],'INTENT_ONLY_MANUAL_REVIEW')
    def test_stale(self):
        self.t._write(self.intent)
        with patch.object(self.t,'inspect',return_value={'status':'INTENT_ONLY_MANUAL_REVIEW'}):
            self.assertEqual(self.r.inspect(now=30,max_age_seconds=20)['status'],'STALE_INTENT_MANUAL_REVIEW')
    def test_future(self):
        self.t._write(self.intent)
        with patch.object(self.t,'inspect',return_value={'status':'INTENT_ONLY_MANUAL_REVIEW'}):
            self.assertEqual(self.r.inspect(now=4,max_age_seconds=20)['status'],'FUTURE_INTENT_MANUAL_REVIEW')
    def test_invalid_times(self):
        with self.assertRaises(TransitionReconciliationError):self.r.inspect(now=-1,max_age_seconds=20)
    def test_hash_verifies(self):self.assertTrue(self.r.verify_evidence(self.r.inspect(now=10,max_age_seconds=20)))
    def test_tamper(self):
        e=self.r.inspect(now=10,max_age_seconds=20);e['status']='PUBLISHED_AWAITING_OPERATOR_ACK'
        with self.assertRaises(TransitionReconciliationError):self.r.verify_evidence(e)
    def test_no_confirmation(self):
        e=self.r.inspect(now=10,max_age_seconds=20)
        with self.assertRaises(TransitionReconciliationError):self.r.acknowledge(e,operator_confirmed=False,now=10,max_age_seconds=20)
    def test_stale_evidence(self):
        e=self.r.inspect(now=10,max_age_seconds=20)
        with self.assertRaises(TransitionReconciliationError):self.r.acknowledge(e,operator_confirmed=True,now=31,max_age_seconds=20)
    def test_no_automatic_ack(self):
        e=self.r.inspect(now=10,max_age_seconds=20)
        with self.assertRaises(TransitionReconciliationError):self.r.acknowledge(e,operator_confirmed=True,now=10,max_age_seconds=20)
    def test_concurrent_lock(self):
        self.r.lock_path.touch()
        with self.r.lock_path.open('rb') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(TransitionReconciliationError):self.r.inspect(now=10,max_age_seconds=20)
    def test_success_ack(self):
        self.t._write(self.intent)
        with patch.object(self.t,'inspect',return_value={'status':'PUBLISHED_AWAITING_OPERATOR_ACK'}):
            e=self.r.inspect(now=10,max_age_seconds=20)
            with patch.object(self.t,'acknowledge',return_value={'status':'TRANSITION_ACKNOWLEDGED'}) as ack:
                self.assertEqual(self.r.acknowledge(e,operator_confirmed=True,now=10,max_age_seconds=20)['status'],'TRANSITION_ACKNOWLEDGED')
                ack.assert_called_once()
    def test_changed_intent(self):
        self.t._write(self.intent)
        with patch.object(self.t,'inspect',return_value={'status':'PUBLISHED_AWAITING_OPERATOR_ACK'}):e=self.r.inspect(now=10,max_age_seconds=20)
        self.t._write({**self.intent,'new_limit':11})
        with self.assertRaises(TransitionReconciliationError):self.r.acknowledge(e,operator_confirmed=True,now=10,max_age_seconds=20)
    def test_lock_path_collision(self):
        with self.assertRaises(TransitionReconciliationError):TransitionReconciler(self.t,lock_path=self.t.intent)

if __name__=='__main__':unittest.main()
