import unittest
from unittest.mock import patch
from workload_profiles_v22845 import measure_profile

class TestProfiles(unittest.TestCase):
    def test_reject_unknown(self):
        with self.assertRaises(ValueError):measure_profile('unknown')
    def test_reject_zero_repetitions(self):
        with self.assertRaises(ValueError):measure_profile('tiny',0)
    @patch('workload_profiles_v22845.run_case')
    def test_medians_from_measured_runs(self, run):
        run.side_effect=lambda size:{'total_ns':size*100,'exclusive_stages_ns':{'copy.native_posix':size*40}}
        result=measure_profile('tiny',2)
        self.assertEqual(len(result['cases']),3)
        self.assertEqual(result['cases'][0]['median_total_ms'],0.4096)
        self.assertEqual(result['cases'][0]['median_exclusive_ms']['copy.native_posix'],0.1638)
        self.assertEqual(len(result['cases'][0]['raw_runs']),2)
if __name__=='__main__':unittest.main()
