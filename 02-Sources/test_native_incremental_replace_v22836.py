"""V228.36: local POSIX path-replacement race regression tests."""
from unittest.mock import patch
from test_native_incremental_executor import ExecutorTests
from native_posix_migration import MigrationBlocked

class ReplacementRaceTests(ExecutorTests):
    def _run_replacement(self, root, call_number):
        from native_incremental_executor import _verified_hash
        calls = [0]
        def race(fd, *, expected):
            digest = _verified_hash(fd, expected=expected)
            calls[0] += 1
            if calls[0] == call_number:
                original = root / 'new'
                displaced = root / 'new.displaced'
                original.rename(displaced)
                original.write_bytes(displaced.read_bytes())
            return digest
        with patch('native_incremental_executor._verified_hash', side_effect=race):
            with self.assertRaises(MigrationBlocked):
                self.executor.execute_claimed(self.plan, 'new', claim_token=self.token)
        self.assertEqual(self.planner.inspect(self.plan)['tasks'][0]['status'], 'CLAIMED')
        self.assertFalse(self.planner.db.in_transaction)

    def test_source_replaced_same_content_during_final_hash(self):
        self._run_replacement(self.src, 3)

    def test_target_replaced_same_content_during_final_hash(self):
        self._run_replacement(self.dst, 4)
