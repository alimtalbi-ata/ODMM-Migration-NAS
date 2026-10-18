import unittest
from baseline_v22841 import summarize
class BaselineTests(unittest.TestCase):
 def setUp(self): self.payload={'benchmark':'local','cases':[{'size_bytes':1024,'runs':[{'total_ns':1000000,'stages_ns':{'commit':800000}},{'total_ns':2000000,'stages_ns':{'commit':1600000}},{'total_ns':3000000,'stages_ns':{'commit':2400000}}]}]}
 def test_median(self): self.assertEqual(summarize(self.payload)['cases'][0]['median_ms'],2)
 def test_deterministic(self): self.assertEqual(summarize(self.payload),summarize(self.payload))
 def test_overlap_warning(self): self.assertFalse(summarize(self.payload)['cases'][0]['additive_stage_costs'])
 def test_invalid(self):
  self.payload['cases'][0]['runs'][0]['total_ns']=0
  with self.assertRaises(ValueError):summarize(self.payload)
 def test_bootstrap_bounds(self):
  x=summarize(self.payload)['cases'][0]['bootstrap_median_95pct_ms'];self.assertTrue(1<=x[0]<=x[1]<=3)
if __name__=='__main__':unittest.main()
