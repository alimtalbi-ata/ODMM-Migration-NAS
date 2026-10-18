import sqlite3
import unittest
from ldaps_crash_recovery import CrashRecoveryCoordinator
from ldaps_recovery_plan import build_recovery_plan,verify_recovery_plan,RecoveryPlanError

class FakeLedger:
    def __init__(self):
        self.db=sqlite3.connect(':memory:',isolation_level=None)

class TestRecoveryPlan(unittest.TestCase):
    def setUp(self):
        self.ledger=FakeLedger();self.c=CrashRecoveryCoordinator(self.ledger)
    def tearDown(self):self.ledger.db.close()
    def plan(self):return build_recovery_plan(self.c,now=100,max_age_seconds=50)
    def test_empty(self):self.assertEqual(self.plan()['report']['status'],'NO_ATTEMPTS_NOT_AUTHORIZED')
    def test_interrupted(self):
        self.c.begin('a',80);p=self.plan();self.assertEqual(p['report']['attempts'][0]['effective_state'],'INTERRUPTED')
    def test_success_present(self):
        self.c.begin('a',80);self.c.journal.append('a',81,'SUCCESS','a'*64)
        self.assertEqual(self.plan()['report']['attempts'][0]['effective_state'],'COMMITTED')
    def test_failure_present(self):
        self.c.begin('a',80);self.c.journal.append('a',81,'NETWORK_FAILURE')
        self.assertEqual(self.plan()['report']['attempts'][0]['effective_state'],'FAILED')
    def test_stale(self):
        self.c.begin('a',1);self.assertEqual(self.plan()['report']['attempts'][0]['action'],'REVIEW_STALE_ATTEMPT')
    def test_future(self):
        self.c.begin('a',120);self.assertEqual(self.plan()['report']['attempts'][0]['action'],'INVESTIGATE_FUTURE_TIMESTAMP')
    def test_read_only(self):
        self.c.begin('a',80);self.plan();self.assertEqual(self.c.inspect('a')['state'],'STARTED')
    def test_deterministic(self):self.assertEqual(self.plan(),self.plan())
    def test_verify(self):self.assertTrue(verify_recovery_plan(self.plan(),self.c,now=100,max_age_seconds=50))
    def test_tampered_bundle(self):
        b=self.plan();b['report']['status']='OK'
        with self.assertRaises(RecoveryPlanError):verify_recovery_plan(b,self.c,now=100,max_age_seconds=50)
    def test_invalid_time(self):
        with self.assertRaises(RecoveryPlanError):build_recovery_plan(self.c,now=-1,max_age_seconds=50)
    def test_tampered_journal(self):
        self.c.begin('a',80);self.c.journal.append('a',81,'SUCCESS','a'*64)
        self.ledger.db.execute("UPDATE directory_sync_events SET status='NETWORK_FAILURE'")
        with self.assertRaises(Exception):self.plan()
    def test_no_auto_cutover(self):
        self.c.begin('a',80);p=self.plan()['report'];self.assertFalse(p['cutover_authorized']);self.assertFalse(p['automatic_retry'])
    def test_contradictory_state(self):
        self.c.begin('a',80);self.c._finish('a','COMMITTED')
        self.assertEqual(self.plan()['report']['attempts'][0]['action'],'INVESTIGATE_CONTRADICTORY_EVIDENCE')

if __name__=='__main__':unittest.main()
