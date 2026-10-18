import sqlite3,unittest
from ldaps_crash_recovery import CrashRecoveryCoordinator
from ldaps_recovery_plan import build_recovery_plan
from ldaps_supervised_recovery import SupervisedRecovery
from ldaps_recovery_dispatch import RecoveryDispatcher
from ldaps_recovery_lease import RecoveryLease
from ldaps_lease_finalization import LeasedFinalizer
from ldaps_effect_fence import EffectFence,EffectFenceError
class Ledger:
    def __init__(self):self.db=sqlite3.connect(':memory:',isolation_level=None)
class Tests(unittest.TestCase):
    def setUp(self):
        self.l=Ledger();self.addCleanup(self.l.db.close)
        c=CrashRecoveryCoordinator(self.l);c.begin('old',80)
        SupervisedRecovery(c).decide(plan=build_recovery_plan(c,now=100,max_age_seconds=50),original_event_id='old',review_id='r1',reviewer='op1',decision='APPROVE_NEW_ATTEMPT',new_event_id='new',now=100,max_age_seconds=50)
        RecoveryDispatcher(c).claim(review_id='r1',owner='w1',at=101)
        self.lease=RecoveryLease(c);self.finalizer=LeasedFinalizer(c);self.f=EffectFence(c)
        self.lease.transition(event_id='new',owner='w1',epoch=1,now=102,ttl=10,action='START')
    def permit(self,**kw):return self.f.authorize(event_id='new',owner=kw.get('owner','w1'),epoch=kw.get('epoch',1),now=kw.get('now',105),operation=kw.get('operation','READ_ONLY_SYNC'))
    def test_success(self):self.assertEqual(self.permit()['status'],'LOCAL_PRE_EFFECT_PERMIT')
    def test_no_external_effect(self):self.assertFalse(self.permit()['external_effect_executed'])
    def test_no_external_fencing(self):self.assertFalse(self.permit()['external_fencing_enforced'])
    def test_no_cutover(self):self.assertFalse(self.permit()['cutover_authorized'])
    def test_verify(self):self.permit();self.assertEqual(self.f.verify()['count'],1)
    def test_multiple_permits(self):self.permit();self.permit();self.assertEqual(self.f.verify()['count'],2)
    def test_wrong_owner(self):
        with self.assertRaisesRegex(EffectFenceError,'STALE'):self.permit(owner='w2')
    def test_wrong_epoch(self):
        with self.assertRaisesRegex(EffectFenceError,'STALE'):self.permit(epoch=2)
    def test_expired(self):
        with self.assertRaisesRegex(EffectFenceError,'STALE'):self.permit(now=112)
    def test_before_claim(self):
        with self.assertRaisesRegex(EffectFenceError,'STALE'):self.permit(now=100)
    def test_transfer_stale(self):
        self.lease.transition(event_id='new',owner='w2',epoch=2,now=112,ttl=10,action='TRANSFER')
        with self.assertRaisesRegex(EffectFenceError,'STALE'):self.permit(now=113)
        self.assertEqual(self.permit(owner='w2',epoch=2,now=113)['epoch'],2)
    def test_after_finalization(self):
        self.finalizer.finish(event_id='new',owner='w1',epoch=1,at=106,outcome='FINISHED')
        with self.assertRaisesRegex(EffectFenceError,'STALE'):self.permit(now=107)
    def test_audit_tamper(self):
        self.permit();self.l.db.execute("UPDATE ldaps_effect_permits SET owner='evil'")
        with self.assertRaisesRegex(EffectFenceError,'TAMPERED'):self.f.verify()
    def test_rollback(self):
        self.l.db.execute("CREATE TRIGGER block_effect BEFORE INSERT ON ldaps_effect_permits BEGIN SELECT RAISE(FAIL,'blocked'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.permit()
        self.assertEqual(self.f.verify()['count'],0)
    def test_invalid(self):
        with self.assertRaises(EffectFenceError):self.permit(epoch=True)
if __name__=='__main__':unittest.main()
