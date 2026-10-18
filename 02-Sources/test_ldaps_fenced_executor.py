import sqlite3,unittest
from ldaps_crash_recovery import CrashRecoveryCoordinator
from ldaps_recovery_plan import build_recovery_plan
from ldaps_supervised_recovery import SupervisedRecovery
from ldaps_recovery_dispatch import RecoveryDispatcher
from ldaps_recovery_lease import RecoveryLease
from ldaps_fenced_executor import FencedExecutionAdapter,SimulatedFencedTarget,FencedExecutionError
class Ledger:
    def __init__(self):self.db=sqlite3.connect(':memory:',isolation_level=None)
class Tests(unittest.TestCase):
    def setUp(self):
        l=Ledger();self.addCleanup(l.db.close)
        c=CrashRecoveryCoordinator(l);c.begin('old',80)
        SupervisedRecovery(c).decide(plan=build_recovery_plan(c,now=100,max_age_seconds=50),original_event_id='old',review_id='r1',reviewer='op1',decision='APPROVE_NEW_ATTEMPT',new_event_id='new',now=100,max_age_seconds=50)
        RecoveryDispatcher(c).claim(review_id='r1',owner='w1',at=101)
        self.lease=RecoveryLease(c);self.lease.transition(event_id='new',owner='w1',epoch=1,now=102,ttl=10,action='START')
        self.target=SimulatedFencedTarget();self.target.advance_epoch('new',1)
        self.adapter=FencedExecutionAdapter(c,self.target);self.db=l.db
    def execute(self,**kw):
        return self.adapter.execute(event_id='new',owner=kw.get('owner','w1'),epoch=kw.get('epoch',1),now=kw.get('now',105),operation='READ_ONLY_SYNC',request_id=kw.get('request_id','req1'))
    def test_success(self):self.assertEqual(self.execute()['status'],'SIMULATED_FENCED_EFFECT_RECORDED')
    def test_no_external(self):self.assertFalse(self.execute()['external_effect_executed'])
    def test_no_cutover(self):self.assertFalse(self.execute()['cutover_authorized'])
    def test_verify(self):self.execute();self.assertEqual(self.adapter.verify()['count'],1)
    def test_duplicate(self):
        self.execute()
        with self.assertRaisesRegex(FencedExecutionError,'DUPLICATE'):self.execute()
    def test_stale_target(self):
        self.target.advance_epoch('new',2)
        with self.assertRaisesRegex(FencedExecutionError,'TARGET_FENCING'):self.execute()
    def test_old_epoch_cannot_advance(self):
        self.target.advance_epoch('new',2)
        with self.assertRaisesRegex(FencedExecutionError,'STALE_EPOCH'):self.target.advance_epoch('new',1)
    def test_wrong_owner(self):
        with self.assertRaises(ValueError):self.execute(owner='other')
    def test_expired(self):
        with self.assertRaises(ValueError):self.execute(now=112)
    def test_transfer(self):
        self.lease.transition(event_id='new',owner='w2',epoch=2,now=112,ttl=10,action='TRANSFER')
        self.target.advance_epoch('new',2)
        with self.assertRaises(ValueError):self.execute(now=113)
        self.assertEqual(self.execute(owner='w2',epoch=2,now=113)['status'],'SIMULATED_FENCED_EFFECT_RECORDED')
    def test_receipt_tamper(self):
        self.execute();self.db.execute("UPDATE ldaps_simulated_effect_receipts SET owner='evil'")
        with self.assertRaisesRegex(FencedExecutionError,'TAMPERED'):self.adapter.verify()
    def test_receipt_failure_reconcile(self):
        self.db.execute("CREATE TRIGGER fail_receipt BEFORE INSERT ON ldaps_simulated_effect_receipts BEGIN SELECT RAISE(FAIL,'blocked'); END")
        with self.assertRaisesRegex(FencedExecutionError,'MANUAL_RECONCILIATION'):self.execute()
        self.assertEqual(len(self.target.effects),1)
    def test_reject_real_target(self):
        with self.assertRaisesRegex(FencedExecutionError,'SIMULATED_TARGET_ONLY'):FencedExecutionAdapter(None,object())
    def test_invalid_epoch(self):
        with self.assertRaisesRegex(FencedExecutionError,'INVALID_EPOCH'):self.target.advance_epoch('new',True)
    def test_second_request(self):
        self.execute();self.execute(request_id='req2');self.assertEqual(self.adapter.verify()['count'],2)
if __name__=='__main__':unittest.main()
