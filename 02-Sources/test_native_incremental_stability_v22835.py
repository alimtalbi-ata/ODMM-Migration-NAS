"""V228.35: external-writer race tests. Local POSIX only, not a snapshot guarantee."""
from unittest.mock import patch
from test_native_incremental_executor import ExecutorTests
from native_posix_migration import MigrationBlocked


class StabilityBoundaryTests(ExecutorTests):
    def test_external_source_change_during_final_hash_fails_closed(self):
        from native_incremental_executor import _verified_hash
        calls = [0]
        def race(fd, *, expected):
            result = _verified_hash(fd, expected=expected)
            calls[0] += 1
            if calls[0] == 3:  # first file in final transactional verification
                (self.src / 'new').write_bytes(b'external-writer-source')
            return result
        with patch('native_incremental_executor._verified_hash', side_effect=race):
            with self.assertRaises(MigrationBlocked):
                self.executor.execute_claimed(self.plan, 'new', claim_token=self.token)
        self.assertEqual(self.planner.inspect(self.plan)['tasks'][0]['status'], 'CLAIMED')
        self.assertFalse(self.planner.db.in_transaction)

    def test_external_target_change_during_final_hash_fails_closed(self):
        from native_incremental_executor import _verified_hash
        calls = [0]
        def race(fd, *, expected):
            result = _verified_hash(fd, expected=expected)
            calls[0] += 1
            if calls[0] == 4:  # target file in final transactional verification
                (self.dst / 'new').write_bytes(b'external-writer-target')
            return result
        with patch('native_incremental_executor._verified_hash', side_effect=race):
            with self.assertRaises(MigrationBlocked):
                self.executor.execute_claimed(self.plan, 'new', claim_token=self.token)
        self.assertEqual(self.planner.inspect(self.plan)['tasks'][0]['status'], 'CLAIMED')
        self.assertFalse(self.planner.db.in_transaction)
