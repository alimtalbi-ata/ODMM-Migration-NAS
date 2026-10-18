import unittest
from benchmark_diagnosis_v22844 import diagnose

class DiagnosisTests(unittest.TestCase):
    def sample(self):
        return {'cases':[{'size_bytes':1024,'runs':[{'total_ns':100,'exclusive_stages_ns':{'copy':60,'db':10}},{'total_ns':120,'exclusive_stages_ns':{'copy':70,'db':20}}]}]}
    def test_ranks_measured_stages(self):
        report=diagnose(self.sample())['cases'][0]
        self.assertEqual(report['largest_instrumented_stage'],'copy')
        self.assertEqual(report['median_unattributed_ms'],0.0)
    def test_missing_raw_runs(self):
        with self.assertRaises(ValueError):diagnose({'cases':[{'runs':[]}]})
    def test_overlapping_exclusive_invalid(self):
        d=self.sample();d['cases'][0]['runs'][0]['exclusive_stages_ns']['copy']=200
        with self.assertRaises(ValueError):diagnose(d)
    def test_no_instrumentation(self):
        d=self.sample();d['cases'][0]['runs'][0]['exclusive_stages_ns']={};d['cases'][0]['runs'][1]['exclusive_stages_ns']={}
        with self.assertRaises(ValueError):diagnose(d)

if __name__=='__main__':unittest.main()
