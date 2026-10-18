import sqlite3
import unittest
from ldaps_crash_recovery import CrashRecoveryCoordinator
from ldaps_recovery_plan import build_recovery_plan
from ldaps_supervised_recovery import SupervisedRecovery,SupervisedRecoveryError

class Ledger:
    def __init__(self): self.db=sqlite3.connect(':memory:',isolation_level=None)

class Tests(unittest.TestCase):
    def setUp(self):
        self.ledger=Ledger();self.addCleanup(self.ledger.db.close)
        self.c=CrashRecoveryCoordinator(self.ledger)
        self.s=SupervisedRecovery(self.c)
        self.c.begin('old',80)
    def plan(self): return build_recovery_plan(self.c,now=100,max_age_seconds=50)
    def decide(self,**overrides):
        kw=dict(plan=self.plan(),original_event_id='old',review_id='review1',reviewer='operator1',decision='APPROVE_NEW_ATTEMPT',new_event_id='new',now=100,max_age_seconds=50)
        kw.update(overrides)
        return self.s.decide(**kw)
    def test_reservation(self):
        r=self.decide();self.assertEqual(r['status'],'NEW_ATTEMPT_RESERVED_NOT_EXECUTED');self.assertFalse(r['automatic_retry']);self.assertFalse(r['cutover_authorized'])
    def test_no_new_intent_created(self):
        self.decide();self.assertIsNone(self.c.inspect('new'))
    def test_reject(self):
        r=self.decide(decision='REJECT',new_event_id=None);self.assertEqual(r['status'],'REJECTED')
    def test_duplicate(self):
        self.decide()
        with self.assertRaises(SupervisedRecoveryError):self.decide(review_id='review2',new_event_id='new2')
    def test_duplicate_reservation(self):
        self.decide()
        self.c.begin('old2',90)
        with self.assertRaises(SupervisedRecoveryError):self.decide(original_event_id='old2',review_id='review2')
    def test_stale_plan(self):
        old=self.plan();self.c.begin('other',90)
        with self.assertRaisesRegex(SupervisedRecoveryError,'STALE_OR_TAMPERED_PLAN'):self.decide(plan=old)
    def test_modified_plan(self):
        p=self.plan();p['sha256']='0'*64
        with self.assertRaises(SupervisedRecoveryError):self.decide(plan=p)
    def test_committed_not_eligible(self):
        self.c.journal.append('old',81,'SUCCESS','a'*64)
        with self.assertRaisesRegex(SupervisedRecoveryError,'NOT_ELIGIBLE'):self.decide()
    def test_stale_attempt_not_eligible(self):
        with self.assertRaisesRegex(SupervisedRecoveryError,'NOT_ELIGIBLE'):self.decide(now=200,max_age_seconds=50,plan=build_recovery_plan(self.c,now=200,max_age_seconds=50))
    def test_invalid_reviewer(self):
        with self.assertRaises(SupervisedRecoveryError):self.decide(reviewer='bad user')
    def test_reuse_old_id(self):
        with self.assertRaises(SupervisedRecoveryError):self.decide(new_event_id='old')
    def test_tampered_review(self):
        self.decide();self.ledger.db.execute("UPDATE ldaps_recovery_reviews SET reviewer='hacker'")
        with self.assertRaisesRegex(SupervisedRecoveryError,'REVIEW_TAMPERED'):self.s.verify()
    def test_verify(self):
        self.decide();self.assertEqual(self.s.verify()['count'],1)
    def test_rollback(self):
        with self.assertRaises(SupervisedRecoveryError):self.decide(new_event_id='old')
        self.assertEqual(self.s.verify()['count'],0)
    def test_reopen(self):
        self.decide();self.assertEqual(SupervisedRecovery(self.c).verify()['count'],1)

if __name__=='__main__':unittest.main()
