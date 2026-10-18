import unittest
from odmm_compact_model_v2275 import filter_rows, summarize_rows
from odmm_windows_compact_v2275 import VERSION, AUTHOR

class CompactTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{'id': 'NAS-01', 'status': 'RUNNING'}, {'id': 'NAS-02', 'status': 'FAILED'}, {'id': 'NAS-03', 'status': 'COMPLETED'}]
    def test_search(self): self.assertEqual(len(filter_rows(self.rows, 'nas-01')), 1)
    def test_state(self): self.assertEqual(len(filter_rows(self.rows, state='FAILED')), 1)
    def test_combined(self): self.assertEqual(filter_rows(self.rows, 'nas-01', 'FAILED'), [])
    def test_invalid_filter(self):
        with self.assertRaises(ValueError): filter_rows(self.rows, state='INVALID')
    def test_no_mutation(self):
        filtered = filter_rows(self.rows)
        filtered[0]['id'] = 'changed'
        self.assertEqual(self.rows[0]['id'], 'NAS-01')
    def test_summary(self):
        self.assertEqual(summarize_rows(self.rows), {'total': 3, 'running': 1, 'failed': 1, 'completed': 1, 'pending': 0})
    def test_metadata(self):
        self.assertEqual(VERSION, '7.8.5')
        self.assertEqual(AUTHOR, 'Abdelhalim Talbi')
