import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '02-Sources'))
from odmm_ui_diagnostics_v22858 import refresh_message, safe_count

class DiagnosticsTest(unittest.TestCase):
    def test_network_preserves_previous_count(self):
        self.assertIn('3 job(s)', refresh_message('NETWORK', 3))
    def test_payload_explains_failure(self):
        self.assertIn('invalide', refresh_message('PAYLOAD', 0))
    def test_validation_explains_failure(self):
        self.assertIn('incohérents', refresh_message('VALIDATION', 1))
    def test_no_secret_in_pure_messages(self):
        for kind in ('NETWORK', 'PAYLOAD', 'VALIDATION'):
            self.assertNotIn('Bearer', refresh_message(kind, 2))
    def test_count_rejects_nonlist(self):
        with self.assertRaises(ValueError): safe_count({})
    def test_count_accepts_list(self):
        self.assertEqual(safe_count([{}]), 1)

if __name__ == '__main__': unittest.main()
