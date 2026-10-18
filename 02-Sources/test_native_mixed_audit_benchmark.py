import sqlite3
import unittest
from native_mixed_audit_benchmark import mixed_benchmark
from test_native_audit_bridge import BridgeTests, OLD, NEW

class MixedBenchmarkTests(BridgeTests):
    def test_mixed_processes_preserve_source(self):
        self.activate()
        with sqlite3.connect(self.t.db) as db:
            before=db.execute('SELECT COUNT(*) FROM orphan_audit_chain').fetchone()
        result=mixed_benchmark(self.t.db,legacy_key=OLD,segment_keys={'k1':NEW},readers=2,reader_repetitions=4,writer_repetitions=5)
        self.assertEqual(result['status'],'PASS',result)
        self.assertEqual(result['reader_operations'],8)
        self.assertEqual(result['writer_attempts'],5)
        self.assertIn('writer_busy_conflict_rate',result)
        self.assertEqual(result['error_count'],0)
        self.assertTrue(result['source_read_only'])
        self.assertFalse(result['cutover_authorized'])
        self.assertNotIn(OLD.hex(),str(result))
        with sqlite3.connect(self.t.db) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM orphan_audit_chain').fetchone(),before)
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='benchmark_write_probe'").fetchone())
    def test_bounds(self):
        self.activate()
        with self.assertRaises(ValueError):
            mixed_benchmark(self.t.db,legacy_key=OLD,segment_keys={'k1':NEW},readers=0)
    def test_missing_database(self):
        with self.assertRaises(FileNotFoundError):
            mixed_benchmark('/no-such-db',legacy_key=OLD,segment_keys={'k1':NEW})
