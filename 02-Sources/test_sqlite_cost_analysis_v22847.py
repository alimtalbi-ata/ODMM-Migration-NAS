import unittest
from sqlite_cost_analysis_v22847 import analyze, SQLITE_STAGES

class SQLiteCostAnalysisTests(unittest.TestCase):
    def case(self):
        return {'cases':[{'size_bytes':4096,'runs':[{'total_ns':1000000,'exclusive_stages_ns':{k:10000 for k in SQLITE_STAGES}}]}]}
    def test_valid(self):
        result=analyze(self.case());self.assertEqual(result['cases'][0]['median_sqlite_share_pct'],4.0)
    def test_missing_stage(self):
        d=self.case();del d['cases'][0]['runs'][0]['exclusive_stages_ns'][SQLITE_STAGES[0]]
        with self.assertRaises(ValueError):analyze(d)
    def test_overcount(self):
        d=self.case();d['cases'][0]['runs'][0]['total_ns']=1
        with self.assertRaises(ValueError):analyze(d)
    def test_missing_runs(self):
        d=self.case();d['cases'][0]['runs']=[]
        with self.assertRaises(ValueError):analyze(d)

if __name__=='__main__':unittest.main()
