"""Local POSIX migration contract: real filesystem/SQLite tests, not NAS qualification."""
import sys, unittest, tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'02-Sources'))
from native_posix_migration import NativePosixMigration, MigrationBlocked
from native_incremental_inventory import IncrementalInventory
from native_incremental_planner import IncrementalPlanner
from native_incremental_executor import IncrementalExecutor

class LocalNativeContract(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); b=Path(self.tmp.name)
        self.src=b/'source';self.dst=b/'target';self.src.mkdir();self.dst.mkdir();self.db=b/'registry.sqlite'
        self.engine=NativePosixMigration(self.src,self.dst,self.db)
        self.inventory=IncrementalInventory(self.engine);self.planner=IncrementalPlanner(self.inventory)
        self.executor=IncrementalExecutor(self.planner)
        old=self.inventory.capture()['pass_id']
        (self.src/'payload.bin').write_bytes(b'ODMM'*16384)
        new=self.inventory.capture()['pass_id']
        self.plan=self.planner.create(old,new)['plan_id']
        self.token=self.planner.claim_copy(self.plan,'payload.bin')['claim_token']
    def tearDown(self):
        self.engine.close();self.tmp.cleanup()
    def test_verified_copy_and_no_cutover(self):
        result=self.executor.execute_claimed(self.plan,'payload.bin',claim_token=self.token)
        self.assertEqual((self.src/'payload.bin').read_bytes(),(self.dst/'payload.bin').read_bytes())
        self.assertFalse(result['cutover_authorized']);self.assertFalse(result['acl_fidelity_verified'])
    def test_claim_survives_restart(self):
        self.engine.close();self.engine=NativePosixMigration(self.src,self.dst,self.db)
        self.inventory=IncrementalInventory(self.engine);self.planner=IncrementalPlanner(self.inventory)
        self.executor=IncrementalExecutor(self.planner)
        self.assertEqual(self.executor.execute_claimed(self.plan,'payload.bin',claim_token=self.token)['status'],'VERIFIED_POSIX_SUBSET')
    def test_wrong_token_fails_closed(self):
        with self.assertRaises(MigrationBlocked):self.executor.execute_claimed(self.plan,'payload.bin',claim_token='invalid')
        self.assertFalse((self.dst/'payload.bin').exists())
    def test_changed_source_fails_closed(self):
        (self.src/'payload.bin').write_bytes(b'mutated')
        with self.assertRaises(MigrationBlocked):self.executor.execute_claimed(self.plan,'payload.bin',claim_token=self.token)
        self.assertFalse((self.dst/'payload.bin').exists())
    def test_existing_target_not_overwritten(self):
        (self.dst/'payload.bin').write_bytes(b'keep')
        with self.assertRaises(MigrationBlocked):self.executor.execute_claimed(self.plan,'payload.bin',claim_token=self.token)
        self.assertEqual((self.dst/'payload.bin').read_bytes(),b'keep')
    def test_crash_after_publish_requires_reconciliation(self):
        def crash():raise RuntimeError('injected crash after publish')
        with self.assertRaises(RuntimeError):self.executor.execute_claimed(self.plan,'payload.bin',claim_token=self.token,after_publish=crash)
        self.assertTrue((self.dst/'payload.bin').exists())
        with self.assertRaises(MigrationBlocked):self.executor.execute_claimed(self.plan,'payload.bin',claim_token=self.token)
        with self.assertRaises(MigrationBlocked):self.executor.acknowledge_reconciled(self.plan,'payload.bin',claim_token=self.token)
        self.engine.reconcile('payload.bin',operator_confirmed=True)
        result=self.executor.acknowledge_reconciled(self.plan,'payload.bin',claim_token=self.token,operator_confirmed=True)
        self.assertFalse(result['cutover_authorized'])
    def test_no_implicit_second_copy(self):
        self.executor.execute_claimed(self.plan,'payload.bin',claim_token=self.token)
        with self.assertRaises(MigrationBlocked):self.executor.execute_claimed(self.plan,'payload.bin',claim_token=self.token)

if __name__=='__main__':unittest.main()
