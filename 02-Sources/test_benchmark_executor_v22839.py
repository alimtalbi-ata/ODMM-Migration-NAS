import unittest
from benchmark_executor_v22839 import benchmark,run_case

class BenchmarkExecutorTests(unittest.TestCase):
    def test_real_path(self):
        result=run_case(1024)
        self.assertGreater(result['total_ns'],0)
        self.assertIn('commit.sqlite_transaction',result['stages_ns'])
        self.assertGreaterEqual(result['stage_counts'].get('verify.source_sha256',0),2)
    def test_aggregation(self):
        result=benchmark((2048,),2)
        self.assertEqual(len(result['cases'][0]['runs']),2)
        self.assertGreater(result['cases'][0]['median_total_ms'],0)
    def test_reject_invalid(self):
        with self.assertRaises(ValueError):benchmark((0,),1)
        with self.assertRaises(ValueError):benchmark((1024,),0)
if __name__=='__main__':unittest.main()
