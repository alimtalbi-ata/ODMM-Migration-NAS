import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked
from native_incremental_inventory import IncrementalInventory
from native_incremental_planner import IncrementalPlanner

class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); base=Path(self.temp.name)
        self.src=base/'src';self.dst=base/'dst';self.src.mkdir();self.dst.mkdir()
        self.engine=NativePosixMigration(self.src,self.dst,base/'db.sqlite')
        self.inv=IncrementalInventory(self.engine);self.planner=IncrementalPlanner(self.inv)
    def tearDown(self):
        self.engine.close();self.temp.cleanup()
    def plan(self):
        (self.src/'old').write_text('a');(self.src/'change').write_text('b')
        a=self.inv.capture()['pass_id']
        (self.src/'old').unlink();(self.src/'change').write_text('c');(self.src/'new').write_text('d')
        b=self.inv.capture()['pass_id'];return a,b,self.planner.create(a,b)
    def test_create_actions(self):
        *_,p=self.plan();self.assertEqual([(t['path'],t['action']) for t in p['tasks']],[('change','COPY'),('new','COPY'),('old','DELETE_REVIEW')])
    def test_no_delete_claim(self):
        *_,p=self.plan()
        with self.assertRaises(MigrationBlocked):self.planner.claim_copy(p['plan_id'],'old')
    def test_idempotent(self):
        a,b,p=self.plan();self.assertEqual(self.planner.create(a,b)['plan_id'],p['plan_id'])
    def test_claim_single(self):
        *_,p=self.plan();self.planner.claim_copy(p['plan_id'],'new')
        with self.assertRaises(MigrationBlocked):self.planner.claim_copy(p['plan_id'],'new')
    def test_reset_confirmation(self):
        *_,p=self.plan();token=self.planner.claim_copy(p['plan_id'],'new')['claim_token']
        with self.assertRaises(MigrationBlocked):self.planner.reset_interrupted(p['plan_id'],'new',claim_token=token)
        self.assertEqual(self.planner.reset_interrupted(p['plan_id'],'new',claim_token=token,operator_confirmed=True)['status'],'RESET_BY_OPERATOR')
    def test_wrong_claim(self):
        *_,p=self.plan();self.planner.claim_copy(p['plan_id'],'new')
        with self.assertRaises(MigrationBlocked):self.planner.reset_interrupted(p['plan_id'],'new',claim_token='fake',operator_confirmed=True)
    def test_restart_claim_durable(self):
        *_,p=self.plan();self.planner.claim_copy(p['plan_id'],'new');self.engine.close()
        self.engine=NativePosixMigration(self.src,self.dst,Path(self.temp.name)/'db.sqlite');self.inv=IncrementalInventory(self.engine);self.planner=IncrementalPlanner(self.inv)
        self.assertEqual(next(t for t in self.planner.inspect(p['plan_id'])['tasks'] if t['path']=='new')['status'],'CLAIMED')
    def test_tamper_tasks(self):
        *_,p=self.plan();self.engine.db.execute('DELETE FROM incremental_tasks WHERE plan_id=? AND path=?',(p['plan_id'],'old'))
        with self.assertRaises(MigrationBlocked):self.planner.inspect(p['plan_id'])
    def test_tamper_inventory(self):
        a,b,p=self.plan();self.engine.db.execute('UPDATE inventory_entries SET size=999 WHERE pass_id=?',(b,))
        with self.assertRaises(MigrationBlocked):self.planner.inspect(p['plan_id'])
    def test_unknown(self):
        with self.assertRaises(MigrationBlocked):self.planner.inspect('unknown')
    def test_identical(self):
        a=self.inv.capture()['pass_id']
        with self.assertRaises(MigrationBlocked):self.planner.create(a,a)
    def test_no_copy_automatically(self):
        *_,p=self.plan();self.planner.claim_copy(p['plan_id'],'new');self.assertFalse((self.dst/'new').exists())
    def test_no_mark_without_native_commit(self):
        *_,p=self.plan();token=self.planner.claim_copy(p['plan_id'],'new')['claim_token']
        with self.assertRaises(MigrationBlocked):self.planner.record_verified(p['plan_id'],'new',claim_token=token)
    def test_reset_blocked_native_intent(self):
        *_,p=self.plan();token=self.planner.claim_copy(p['plan_id'],'new')['claim_token']
        self.engine.db.execute('INSERT INTO intents VALUES (?,?,?,?,?)',('new',1,'x',0,0))
        with self.assertRaises(MigrationBlocked):self.planner.reset_interrupted(p['plan_id'],'new',claim_token=token,operator_confirmed=True)
    def test_missing_pass(self):
        a=self.inv.capture()['pass_id']
        with self.assertRaises(MigrationBlocked):self.planner.create(a,'missing')

if __name__=='__main__':unittest.main()
