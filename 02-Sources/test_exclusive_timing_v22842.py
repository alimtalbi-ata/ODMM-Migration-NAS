import unittest
from exclusive_timing_v22842 import exclusive_timings
class ExclusiveTimingTests(unittest.TestCase):
    def test_nested(self):
        events=[dict(stage='transaction',start_ns=0,end_ns=100),dict(stage='hash',start_ns=20,end_ns=50)]
        self.assertEqual(exclusive_timings(events),{'transaction':70,'hash':30})
    def test_overlapping_children_union(self):
        e=[dict(stage='outer',start_ns=0,end_ns=100),dict(stage='a',start_ns=10,end_ns=40),dict(stage='b',start_ns=30,end_ns=60)]
        self.assertEqual(exclusive_timings(e)['outer'],50)
    def test_missing_interval_rejected(self):
        with self.assertRaises(ValueError):exclusive_timings([dict(stage='legacy',elapsed_ns=4)])
    def test_negative_rejected(self):
        with self.assertRaises(ValueError):exclusive_timings([dict(stage='bad',start_ns=5,end_ns=2)])
if __name__=='__main__':unittest.main()
