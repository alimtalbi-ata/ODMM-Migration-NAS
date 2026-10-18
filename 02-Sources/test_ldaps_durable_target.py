import os,sqlite3,tempfile,unittest
from ldaps_durable_target import DurableFencedTarget,DurableTargetError,DurableEffectReconciler
from ldaps_fenced_executor import FencedExecutionAdapter,FencedExecutionError
from ldaps_crash_recovery import CrashRecoveryCoordinator
from ldaps_recovery_plan import build_recovery_plan
from ldaps_supervised_recovery import SupervisedRecovery
from ldaps_recovery_dispatch import RecoveryDispatcher
from ldaps_recovery_lease import RecoveryLease
class Ledger:
    def __init__(self,db):self.db=db
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=os.path.join(self.tmp.name,'target.sqlite')
        self.targetdb=sqlite3.connect(self.path,isolation_level=None);self.addCleanup(self.targetdb.close)
        self.target=DurableFencedTarget(self.targetdb)
        self.db=sqlite3.connect(':memory:',isolation_level=None);self.addCleanup(self.db.close)
        self.coordinator=CrashRecoveryCoordinator(Ledger(self.db));self.coordinator.begin('old',80)
        SupervisedRecovery(self.coordinator).decide(plan=build_recovery_plan(self.coordinator,now=100,max_age_seconds=50),original_event_id='old',review_id='r1',reviewer='op1',decision='APPROVE_NEW_ATTEMPT',new_event_id='new',now=100,max_age_seconds=50)
        RecoveryDispatcher(self.coordinator).claim(review_id='r1',owner='w1',at=101)
        self.lease=RecoveryLease(self.coordinator);self.lease.transition(event_id='new',owner='w1',epoch=1,now=102,ttl=10,action='START')
        self.target.advance_epoch('new',1)
    def effect(self,**kw):
        return self.target.apply(event_id='new',owner=kw.get('owner','w1'),epoch=kw.get('epoch',1),operation=kw.get('operation','READ_ONLY_SYNC'),permit_hash=kw.get('permit_hash','hash'),request_id=kw.get('request_id','req'))
    def test_apply(self):self.assertEqual(self.effect()['status'],'SIMULATED_EFFECT_APPLIED')
    def test_idempotent(self):self.effect();self.assertEqual(self.effect()['status'],'ALREADY_APPLIED')
    def test_conflict(self):
        self.effect()
        with self.assertRaisesRegex(DurableTargetError,'IDEMPOTENCY_CONFLICT'):self.effect(operation='OTHER')
    def test_reopen(self):
        self.effect();other=sqlite3.connect(self.path,isolation_level=None)
        try:self.assertEqual(DurableFencedTarget(other).lookup('new','req')['operation'],'READ_ONLY_SYNC')
        finally:other.close()
    def test_reopen_idempotent(self):
        self.effect();other=sqlite3.connect(self.path,isolation_level=None)
        try:self.assertEqual(DurableFencedTarget(other).apply(event_id='new',owner='w1',epoch=1,operation='READ_ONLY_SYNC',permit_hash='hash',request_id='req')['status'],'ALREADY_APPLIED')
        finally:other.close()
    def test_stale_epoch(self):
        self.target.advance_epoch('new',2)
        with self.assertRaisesRegex(DurableTargetError,'TARGET_FENCING'):self.effect()
    def test_epoch_rollback(self):
        self.target.advance_epoch('new',2)
        with self.assertRaisesRegex(DurableTargetError,'STALE_EPOCH'):self.target.advance_epoch('new',1)
    def test_target_tamper(self):
        self.effect();self.targetdb.execute("UPDATE durable_target_effects SET operation='tampered'")
        with self.assertRaisesRegex(DurableTargetError,'TAMPERED'):self.target.verify()
    def test_not_applied(self):
        self.assertEqual(DurableEffectReconciler(self.coordinator,self.target).inspect('new','req')['state'],'NOT_APPLIED')
    def test_uncertain_commit(self):
        self.effect();r=DurableEffectReconciler(self.coordinator,self.target).inspect('new','req')
        self.assertEqual(r['state'],'TARGET_COMMITTED_RECEIPT_MISSING');self.assertFalse(r['automatic_retry'])
    def test_receipt_without_target(self):
        self.db.execute('CREATE TABLE ldaps_simulated_effect_receipts(request_id TEXT,event_id TEXT,target_hash TEXT)')
        self.db.execute("INSERT INTO ldaps_simulated_effect_receipts VALUES ('req','new','abc')")
        self.assertEqual(DurableEffectReconciler(self.coordinator,self.target).inspect('new','req')['state'],'RECEIPT_WITHOUT_TARGET')
    def test_consistent(self):
        h=self.effect()['evidence_sha256'];self.db.execute('CREATE TABLE ldaps_simulated_effect_receipts(request_id TEXT,event_id TEXT,target_hash TEXT)')
        self.db.execute('INSERT INTO ldaps_simulated_effect_receipts VALUES (?,?,?)',('req','new',h))
        self.assertEqual(DurableEffectReconciler(self.coordinator,self.target).inspect('new','req')['state'],'CONSISTENT')
    def test_mismatch(self):
        self.effect();self.db.execute('CREATE TABLE ldaps_simulated_effect_receipts(request_id TEXT,event_id TEXT,target_hash TEXT)')
        self.db.execute("INSERT INTO ldaps_simulated_effect_receipts VALUES ('req','new','wrong')")
        self.assertEqual(DurableEffectReconciler(self.coordinator,self.target).inspect('new','req')['state'],'EVIDENCE_MISMATCH')
    def test_no_cutover(self):self.assertFalse(self.effect()['cutover_authorized'])
    def test_bad_epoch(self):
        with self.assertRaisesRegex(DurableTargetError,'INVALID_EPOCH'):self.target.advance_epoch('new',True)
if __name__=='__main__':unittest.main()
