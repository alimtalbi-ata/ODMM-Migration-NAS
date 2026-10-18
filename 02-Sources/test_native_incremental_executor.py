import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration,MigrationBlocked
from native_incremental_inventory import IncrementalInventory
from native_incremental_planner import IncrementalPlanner
from native_incremental_executor import IncrementalExecutor

class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();base=Path(self.temp.name)
        self.src=base/'src';self.dst=base/'dst';self.src.mkdir();self.dst.mkdir()
        self.db=base/'state.sqlite'
        self.engine=NativePosixMigration(self.src,self.dst,self.db)
        self.inv=IncrementalInventory(self.engine);self.planner=IncrementalPlanner(self.inv)
        self.executor=IncrementalExecutor(self.planner)
        first=self.inv.capture()['pass_id']
        (self.src/'new').write_bytes(b'payload')
        second=self.inv.capture()['pass_id']
        self.plan=self.planner.create(first,second)['plan_id']
        self.token=self.planner.claim_copy(self.plan,'new')['claim_token']
    def tearDown(self):
        self.engine.close();self.temp.cleanup()
    def run_copy(self):return self.executor.execute_claimed(self.plan,'new',claim_token=self.token)
    def test_timing_instrumentation_on_success(self):
        events=[]
        self.executor=IncrementalExecutor(self.planner,timing_sink=events.append)
        self.run_copy()
        stages={e['stage'] for e in events}
        self.assertIn('verify.source_sha256',stages)
        self.assertIn('verify.target_sha256',stages)
        self.assertIn('commit.sqlite_transaction',stages)
        self.assertTrue(all(isinstance(e['elapsed_ns'],int) and e['elapsed_ns']>=0 for e in events))

    def test_broken_observer_does_not_block_copy(self):
        def broken(_):raise RuntimeError('monitor unavailable')
        self.executor=IncrementalExecutor(self.planner,timing_sink=broken)
        self.assertEqual(self.run_copy()['status'],'VERIFIED_POSIX_SUBSET')

    def test_e2e(self):
        result=self.run_copy();self.assertEqual(result['status'],'VERIFIED_POSIX_SUBSET')
        self.assertEqual((self.dst/'new').read_bytes(),b'payload')
        self.assertFalse(result['cutover_authorized'])
    def test_double_execute_blocked(self):
        self.run_copy()
        with self.assertRaises(MigrationBlocked):self.run_copy()
    def test_invalid_token(self):
        with self.assertRaises(MigrationBlocked):self.executor.execute_claimed(self.plan,'new',claim_token='wrong')
        self.assertFalse((self.dst/'new').exists())
    def test_source_modified_since_inventory(self):
        (self.src/'new').write_bytes(b'changed')
        with self.assertRaises(MigrationBlocked):self.run_copy()
        self.assertFalse((self.dst/'new').exists())
    def test_target_exists(self):
        (self.dst/'new').write_bytes(b'existing')
        with self.assertRaises(MigrationBlocked):self.run_copy()
        self.assertEqual((self.dst/'new').read_bytes(),b'existing')
    def test_crash_after_publish(self):
        def crash():raise RuntimeError('simulated crash')
        with self.assertRaises(RuntimeError):self.executor.execute_claimed(self.plan,'new',claim_token=self.token,after_publish=crash)
        self.assertEqual((self.dst/'new').read_bytes(),b'payload')
        with self.assertRaises(MigrationBlocked):self.run_copy()
        with self.assertRaises(MigrationBlocked):self.executor.acknowledge_reconciled(self.plan,'new',claim_token=self.token,operator_confirmed=True)
        self.engine.reconcile('new',operator_confirmed=True)
        self.assertEqual(self.executor.acknowledge_reconciled(self.plan,'new',claim_token=self.token,operator_confirmed=True)['status'],'VERIFIED_POSIX_SUBSET')
    def test_reconcile_requires_operator(self):
        with self.assertRaises(MigrationBlocked):self.executor.acknowledge_reconciled(self.plan,'new',claim_token=self.token)
    def test_reconcile_refuses_changed_target(self):
        def crash():raise RuntimeError('crash')
        with self.assertRaises(RuntimeError):self.executor.execute_claimed(self.plan,'new',claim_token=self.token,after_publish=crash)
        (self.dst/'new').write_bytes(b'bad')
        with self.assertRaises(MigrationBlocked):self.engine.reconcile('new',operator_confirmed=True)
    def test_restart_claim(self):
        self.engine.close();self.engine=NativePosixMigration(self.src,self.dst,self.db)
        self.inv=IncrementalInventory(self.engine);self.planner=IncrementalPlanner(self.inv)
        self.executor=IncrementalExecutor(self.planner)
        self.assertEqual(self.run_copy()['status'],'VERIFIED_POSIX_SUBSET')
    def test_symlink_source_rejected(self):
        (self.src/'new').unlink();(self.src/'new').symlink_to('elsewhere')
        with self.assertRaises(MigrationBlocked):self.run_copy()
    def test_no_implicit_claim(self):
        with self.assertRaises(MigrationBlocked):self.executor.execute_claimed(self.plan,'new',claim_token='')
    def test_ack_requires_native_commit(self):
        with self.assertRaises(MigrationBlocked):self.executor.acknowledge_reconciled(self.plan,'new',claim_token=self.token,operator_confirmed=True)

if __name__=='__main__':unittest.main()
