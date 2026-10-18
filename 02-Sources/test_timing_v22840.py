import unittest
from benchmark_executor_v22839 import run_case, benchmark

class TimingTest(unittest.TestCase):
    def test_copy_stage(self):
        result=run_case(4096)
        self.assertEqual(result['stage_counts'].get('copy.native_posix'),1)
        self.assertGreater(result['stages_ns']['copy.native_posix'],0)
    def test_stage_observability(self):
        result=run_case(4096)
        self.assertIn('verify.source_inventory',result['stages_ns'])
        self.assertIn('commit.sqlite_transaction',result['stages_ns'])
    def test_benchmark_output(self):
        result=benchmark((4096,),1)
        self.assertIn('copy.native_posix',result['cases'][0]['median_stage_ms'])

if __name__=='__main__':unittest.main()
