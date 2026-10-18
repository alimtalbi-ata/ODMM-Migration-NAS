"""Local POSIX tests for final validation immediately before SQLite COMMIT."""
from unittest.mock import patch
from test_native_incremental_executor import ExecutorTests
from native_posix_migration import MigrationBlocked

class FinalGateTests(ExecutorTests):
    def test_source_mutation_between_first_check_and_final_commit_rejected(self):
        original = self.executor._verify_locked
        calls = [0]
        def interposed(path):
            calls[0] += 1
            if calls[0] == 2:
                (self.src / path).write_bytes(b'late-source-mutation')
            return original(path)
        with patch.object(self.executor, '_verify_locked', side_effect=interposed):
            with self.assertRaises(MigrationBlocked):
                self.executor.execute_claimed(self.plan, 'new', claim_token=self.token)
        self.assertGreaterEqual(calls[0], 2)
        self.assertEqual(self.planner.inspect(self.plan)['tasks'][0]['status'], 'CLAIMED')
        self.assertFalse(self.planner.db.in_transaction)

    def test_target_mutation_between_first_check_and_final_commit_rejected(self):
        original = self.executor._verify_locked
        calls = [0]
        def interposed(path):
            calls[0] += 1
            if calls[0] == 2:
                (self.dst / path).write_bytes(b'late-target-mutation')
            return original(path)
        with patch.object(self.executor, '_verify_locked', side_effect=interposed):
            with self.assertRaises(MigrationBlocked):
                self.executor.execute_claimed(self.plan, 'new', claim_token=self.token)
        self.assertEqual(self.planner.inspect(self.plan)['tasks'][0]['status'], 'CLAIMED')
        self.assertFalse(self.planner.db.in_transaction)
