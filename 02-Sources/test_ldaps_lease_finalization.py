import sqlite3,unittest
from ldaps_crash_recovery import CrashRecoveryCoordinator
from ldaps_recovery_plan import build_recovery_plan
from ldaps_supervised_recovery import SupervisedRecovery
from ldaps_recovery_dispatch import RecoveryDispatcher
from ldaps_recovery_lease import RecoveryLease,LeaseError
from ldaps_lease_finalization import LeasedFinalizer,FinalizationError
class Ledger:
    def __init__(self):self.db=sqlite3.connect(':memory:',isolation_level=None)
class Tests(unittest.TestCase):
    def setUp(self):
        self.l=Ledger();self.addCleanup(self.l.db.close)
        c=CrashRecoveryCoordinator(self.l);c.begin('old',80)
        SupervisedRecovery(c).decide(plan=build_recovery_plan(c,now=100,max_age_seconds=50),original_event_id='old',review_id='r1',reviewer='op1',decision='APPROVE_NEW_ATTEMPT',new_event_id='new',now=100,max_age_seconds=50)
        RecoveryDispatcher(c).claim(review_id='r1',owner='w1',at=101)
        self.lease=RecoveryLease(c);self.f=LeasedFinalizer(c)
        self.lease.transition(event_id='new',owner='w1',epoch=1,now=102,ttl=10,action='START')
    def finish(self,**kwargs):return self.f.finish(event_id='new',owner=kwargs.get('owner','w1'),epoch=kwargs.get('epoch',1),at=kwargs.get('at',105),outcome=kwargs.get('outcome','FINISHED'))
    def test_success(self):self.assertEqual(self.finish()['status'],'FINISHED')
    def test_abort(self):self.assertEqual(self.finish(outcome='ABORTED')['status'],'ABORTED')
    def test_verify(self):self.finish();self.assertEqual(self.f.verify()['count'],1)
    def test_duplicate(self):
        self.finish()
        with self.assertRaisesRegex(FinalizationError,'ALREADY_FINALIZED'):self.finish()
    def test_expired(self):
        with self.assertRaisesRegex(FinalizationError,'STALE_OWNER'):self.finish(at=112)
    def test_wrong_owner(self):
        with self.assertRaisesRegex(FinalizationError,'STALE_OWNER'):self.finish(owner='w2')
    def test_wrong_epoch(self):
        with self.assertRaisesRegex(FinalizationError,'STALE_OWNER'):self.finish(epoch=2)
    def test_transfer(self):
        self.lease.transition(event_id='new',owner='w2',epoch=2,now=112,ttl=10,action='TRANSFER')
        self.assertEqual(self.finish(owner='w2',epoch=2,at=113)['epoch'],2)
    def test_old_owner_after_transfer(self):
        self.lease.transition(event_id='new',owner='w2',epoch=2,now=112,ttl=10,action='TRANSFER')
        with self.assertRaisesRegex(FinalizationError,'STALE_OWNER'):self.finish(at=113)
    def test_no_transfer_after_finish(self):
        self.finish()
        with self.assertRaisesRegex(LeaseError,'ALREADY_FINALIZED'):self.lease.transition(event_id='new',owner='w2',epoch=2,now=112,ttl=10,action='TRANSFER')
    def test_rollback(self):
        self.l.db.execute("CREATE TRIGGER fail_final BEFORE INSERT ON ldaps_lease_finalization_events BEGIN SELECT RAISE(FAIL,'blocked'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.finish()
        self.assertEqual(self.f.verify()['count'],0)
    def test_tamper(self):
        self.finish();self.l.db.execute("UPDATE ldaps_lease_finalization_events SET owner='evil'")
        with self.assertRaisesRegex(FinalizationError,'JOURNAL_TAMPERED'):self.f.verify()
    def test_state_tamper(self):
        self.finish();self.l.db.execute("UPDATE ldaps_lease_finalizations SET outcome='ABORTED'")
        with self.assertRaisesRegex(FinalizationError,'STATE_TAMPERED'):self.f.verify()
    def test_no_effect(self):self.assertFalse(self.finish()['external_effect_verified'])
    def test_invalid_outcome(self):
        with self.assertRaisesRegex(FinalizationError,'INVALID_REQUEST'):self.finish(outcome='CUTOVER')
if __name__=='__main__':unittest.main()
