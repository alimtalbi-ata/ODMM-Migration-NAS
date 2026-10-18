import sqlite3,unittest
from ldaps_crash_recovery import CrashRecoveryCoordinator
from ldaps_recovery_plan import build_recovery_plan
from ldaps_supervised_recovery import SupervisedRecovery
from ldaps_recovery_dispatch import RecoveryDispatcher
from ldaps_recovery_lease import RecoveryLease,LeaseError
class Ledger:
    def __init__(self):self.db=sqlite3.connect(':memory:',isolation_level=None)
class Tests(unittest.TestCase):
    def setUp(self):
        l=Ledger();self.addCleanup(l.db.close);self.l=l
        c=CrashRecoveryCoordinator(l);c.begin('old',80)
        SupervisedRecovery(c).decide(plan=build_recovery_plan(c,now=100,max_age_seconds=50),original_event_id='old',review_id='r1',reviewer='op1',decision='APPROVE_NEW_ATTEMPT',new_event_id='new',now=100,max_age_seconds=50)
        self.d=RecoveryDispatcher(c);self.d.claim(review_id='r1',owner='worker1',at=101)
        self.lease=RecoveryLease(c)
    def start(self):return self.lease.transition(event_id='new',owner='worker1',epoch=1,now=102,ttl=10,action='START')
    def test_start(self):self.assertEqual(self.start()['expires_at'],112)
    def test_check(self):self.start();self.assertTrue(self.lease.check(event_id='new',owner='worker1',epoch=1,now=111))
    def test_expiry(self):self.start();self.assertFalse(self.lease.check(event_id='new',owner='worker1',epoch=1,now=112))
    def test_duplicate(self):
        self.start()
        with self.assertRaises(LeaseError):self.start()
    def test_renew(self):
        self.start();self.lease.transition(event_id='new',owner='worker1',epoch=1,now=110,ttl=10,action='RENEW')
        self.assertTrue(self.lease.check(event_id='new',owner='worker1',epoch=1,now=119))
    def test_late_renew(self):
        self.start()
        with self.assertRaisesRegex(LeaseError,'STALE_LEASE'):self.lease.transition(event_id='new',owner='worker1',epoch=1,now=112,ttl=10,action='RENEW')
    def test_transfer(self):
        self.start();self.lease.transition(event_id='new',owner='worker2',epoch=2,now=112,ttl=10,action='TRANSFER')
        self.assertFalse(self.lease.check(event_id='new',owner='worker1',epoch=1,now=113))
        self.assertTrue(self.lease.check(event_id='new',owner='worker2',epoch=2,now=113))
    def test_early_transfer(self):
        self.start()
        with self.assertRaisesRegex(LeaseError,'TRANSFER_NOT_ALLOWED'):self.lease.transition(event_id='new',owner='worker2',epoch=2,now=111,ttl=10,action='TRANSFER')
    def test_same_owner_transfer(self):
        self.start()
        with self.assertRaises(LeaseError):self.lease.transition(event_id='new',owner='worker1',epoch=2,now=112,ttl=10,action='TRANSFER')
    def test_tamper(self):
        self.start();self.l.db.execute("UPDATE ldaps_recovery_leases SET owner='attacker'")
        with self.assertRaisesRegex(LeaseError,'LEASE_STATE_TAMPERED'):self.lease.verify()
    def test_journal_tamper(self):
        self.start();self.l.db.execute("UPDATE ldaps_recovery_lease_events SET owner='attacker'")
        with self.assertRaisesRegex(LeaseError,'LEASE_JOURNAL_TAMPERED'):self.lease.verify()
    def test_rollback(self):
        self.l.db.execute("CREATE TRIGGER fail_lease BEFORE INSERT ON ldaps_recovery_lease_events BEGIN SELECT RAISE(FAIL,'blocked'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.start()
        self.assertEqual(self.lease.verify()['count'],0)
    def test_no_external_effect(self):self.start();self.assertIsNone(self.d.coordinator.inspect('new'))
    def test_bad_ttl(self):
        with self.assertRaisesRegex(LeaseError,'INVALID_REQUEST'):self.lease.transition(event_id='new',owner='worker1',epoch=1,now=102,ttl=0,action='START')
    def test_reopen(self):self.start();self.assertEqual(RecoveryLease(self.d.coordinator).verify()['count'],1)
if __name__=='__main__':unittest.main()
