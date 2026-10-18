import unittest
from bottleneck_report_v22843 import analyze
class ReportTests(unittest.TestCase):
    def test_rank_and_nested(self):
        runs=[[{'stage':'transaction','start_ns':0,'end_ns':10000000},{'stage':'hash','start_ns':1000000,'end_ns':9000000}], [{'stage':'transaction','start_ns':0,'end_ns':12000000},{'stage':'hash','start_ns':2000000,'end_ns':10000000}]]
        result=analyze(runs)
        self.assertEqual(result['ranked_stages'][0]['stage'],'hash')
        self.assertEqual(result['ranked_stages'][1]['median_exclusive_ms'],3)
    def test_no_data(self):
        with self.assertRaises(ValueError):analyze([])
    def test_no_legacy_elapsed(self):
        with self.assertRaises(ValueError):analyze([[{'stage':'hash','elapsed_ns':100}]])
    def test_bad_run(self):
        with self.assertRaises(ValueError):analyze([[]])
if __name__=='__main__':unittest.main()
