import sqlite3,unittest
from ldaps_crash_recovery import CrashRecoveryCoordinator
from ldaps_recovery_plan import build_recovery_plan
from ldaps_supervised_recovery import SupervisedRecovery
from ldaps_recovery_dispatch import RecoveryDispatcher,DispatchError
class Ledger:
    def __init__(self):self.db=sqlite3.connect(':memory:',isolation_level=None)
class Tests(unittest.TestCase):
    def setUp(self):
        self.l=Ledger();self.addCleanup(self.l.db.close)
        self.c=CrashRecoveryCoordinator(self.l);self.c.begin('old',80)
        self.s=SupervisedRecovery(self.c)
        self.s.decide(plan=build_recovery_plan(self.c,now=100,max_age_seconds=50),original_event_id='old',review_id='r1',reviewer='op1',decision='APPROVE_NEW_ATTEMPT',new_event_id='new',now=100,max_age_seconds=50)
        self.d=RecoveryDispatcher(self.c)
    def claim(self,**kw):return self.d.claim(**(dict(review_id='r1',owner='worker1',at=101)|kw))
    def test_claim(self):self.assertEqual(self.claim()['status'],'CLAIMED_NOT_EXECUTED')
    def test_no_automatic_retry(self):self.claim();self.assertIsNone(self.c.inspect('new'))
    def test_duplicate(self):
        self.claim()
        with self.assertRaisesRegex(DispatchError,'ALREADY_CONSUMED'):self.claim(owner='worker2')
    def test_finish(self):
        self.claim();self.assertEqual(self.d.finish(new_event_id='new',owner='worker1',epoch=1,at=102,outcome='FINISH')['status'],'FINISHED')
    def test_abort(self):
        self.claim();self.assertEqual(self.d.finish(new_event_id='new',owner='worker1',epoch=1,at=102,outcome='ABORT')['status'],'ABORTED')
    def test_stale_owner(self):
        self.claim()
        with self.assertRaisesRegex(DispatchError,'STALE_OR_INVALID_OWNER'):self.d.finish(new_event_id='new',owner='other',epoch=1,at=102,outcome='FINISH')
    def test_double_finish(self):
        self.claim();self.d.finish(new_event_id='new',owner='worker1',epoch=1,at=102,outcome='FINISH')
        with self.assertRaises(DispatchError):self.d.finish(new_event_id='new',owner='worker1',epoch=1,at=103,outcome='FINISH')
    def test_time(self):
        with self.assertRaisesRegex(DispatchError,'TIME_BEFORE_REVIEW'):self.claim(at=99)
    def test_tamper(self):
        self.claim();self.l.db.execute("UPDATE ldaps_recovery_dispatch SET owner='evil'")
        with self.assertRaisesRegex(DispatchError,'DISPATCH_STATE_TAMPERED'):self.d.verify()
    def test_event_tamper(self):
        self.claim();self.l.db.execute("UPDATE ldaps_recovery_dispatch_events SET owner='evil'")
        with self.assertRaisesRegex(DispatchError,'EVENT_CHAIN_TAMPERED'):self.d.verify()
    def test_reopen(self):
        self.claim();self.assertEqual(RecoveryDispatcher(self.c).verify()['count'],1)
    def test_rollback(self):
        self.l.db.execute("CREATE TRIGGER fail_event BEFORE INSERT ON ldaps_recovery_dispatch_events BEGIN SELECT RAISE(FAIL,'blocked'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.claim()
        self.assertEqual(self.d.verify()['count'],0)
    def test_unknown_review(self):
        with self.assertRaisesRegex(DispatchError,'NO_APPROVED_RESERVATION'):self.claim(review_id='missing')
    def test_preexisting_intent(self):
        self.c.begin('new',101)
        with self.assertRaisesRegex(DispatchError,'EVENT_ALREADY_EXISTS'):self.claim()
    def test_bad_epoch(self):
        self.claim()
        with self.assertRaisesRegex(DispatchError,'INVALID_TRANSITION'):self.d.finish(new_event_id='new',owner='worker1',epoch=2,at=102,outcome='FINISH')
if __name__=='__main__':unittest.main()
