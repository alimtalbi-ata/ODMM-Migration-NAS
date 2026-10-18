"""V228.33: mutation/reconciliation safety on local POSIX files only."""
import unittest
from test_native_incremental_executor import ExecutorTests
from native_posix_migration import MigrationBlocked

class ConcurrentMutationTests(ExecutorTests):
    def test_source_mutation_after_publish_rejected(self):
        def mutate():
            (self.src/'new').write_bytes(b'changed-after-publish')
        with self.assertRaises(MigrationBlocked):
            self.executor.execute_claimed(self.plan,'new',claim_token=self.token,after_publish=mutate)
        self.assertEqual(self.planner.inspect(self.plan)['tasks'][0]['status'],'CLAIMED')
        with self.assertRaises(MigrationBlocked):self.run_copy()

    def test_target_mutation_after_publish_rejected(self):
        def mutate():
            (self.dst/'new').write_bytes(b'corrupted-target')
        with self.assertRaises(MigrationBlocked):
            self.executor.execute_claimed(self.plan,'new',claim_token=self.token,after_publish=mutate)
        self.assertEqual(self.planner.inspect(self.plan)['tasks'][0]['status'],'CLAIMED')

    def test_reconciliation_rejects_source_change_after_crash(self):
        def crash():raise RuntimeError('injected interruption')
        with self.assertRaises(RuntimeError):
            self.executor.execute_claimed(self.plan,'new',claim_token=self.token,after_publish=crash)
        (self.src/'new').write_bytes(b'source-mutated')
        with self.assertRaises(MigrationBlocked):
            self.executor.acknowledge_reconciled(self.plan,'new',claim_token=self.token,operator_confirmed=True)
        self.assertEqual(self.planner.inspect(self.plan)['tasks'][0]['status'],'CLAIMED')

    def test_reconciliation_rejects_target_change_after_crash(self):
        def crash():raise RuntimeError('injected interruption')
        with self.assertRaises(RuntimeError):
            self.executor.execute_claimed(self.plan,'new',claim_token=self.token,after_publish=crash)
        (self.dst/'new').write_bytes(b'target-mutated')
        with self.assertRaises(MigrationBlocked):
            self.engine.reconcile('new',operator_confirmed=True)
        self.assertEqual(self.planner.inspect(self.plan)['tasks'][0]['status'],'CLAIMED')
