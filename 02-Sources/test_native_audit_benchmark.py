"""V191.5 latency aggregation and real spawned reader smoke tests."""
import unittest
from native_audit_benchmark import benchmark, percentiles
from test_native_audit_bridge import BridgeTests, OLD, NEW

class BenchmarkTests(BridgeTests):
    def test_spawned_readers_report_success_without_keys(self):
        self.activate()
        report=benchmark(self.t.db,legacy_key=OLD,segment_keys={'k1':NEW},workers=2,repetitions=3)
        self.assertEqual(report['status'],'PASS',report)
        self.assertEqual(report['operations'],6)
        self.assertEqual(report['error_count'],0)
        self.assertFalse(report['cutover_authorized'])
        self.assertTrue(report['read_only'])
        self.assertNotIn(OLD.hex(),str(report))
        self.assertNotIn(NEW.hex(),str(report))
    def test_missing_database_rejected(self):
        with self.assertRaises(FileNotFoundError):
            benchmark('/nonexistent/odmm-1915.db',legacy_key=OLD,segment_keys={'k1':NEW})
    def test_bounds_rejected(self):
        with self.assertRaises(ValueError):
            benchmark(self.t.db,legacy_key=OLD,segment_keys={'k1':NEW},workers=0)
    def test_percentile_interpolation(self):
        p=percentiles([1,2,3,4,5])
        self.assertEqual(p['p50_ms'],3)
        self.assertEqual(p['p95_ms'],4.8)
        self.assertEqual(p['p99_ms'],4.96)
    def test_empty_percentiles_rejected(self):
        with self.assertRaises(ValueError):percentiles([])

if __name__=='__main__':unittest.main()
