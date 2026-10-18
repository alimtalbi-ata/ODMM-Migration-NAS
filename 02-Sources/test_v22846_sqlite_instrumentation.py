import unittest
from pathlib import Path

class SQLiteInstrumentationTests(unittest.TestCase):
    def test_commit_stage_metrics_present(self):
        source = (Path(__file__).parent / 'native_incremental_executor.py').read_text()
        for stage in ('commit.claim_lookup', 'commit.claim_update', 'commit.sqlite_commit', 'commit.sqlite_transaction'):
            self.assertIn(repr(stage), source)

    def test_timing_sink_is_fail_open(self):
        from native_incremental_executor import IncrementalExecutor
        obj = IncrementalExecutor.__new__(IncrementalExecutor)
        obj.last_timings=[]
        obj.timing_sink=lambda record: (_ for _ in ()).throw(RuntimeError('observer unavailable'))
        obj._record_timing('commit.claim_lookup', 17, start_ns=12)
        self.assertEqual(obj.last_timings[0]['end_ns'],29)

if __name__ == '__main__': unittest.main()
