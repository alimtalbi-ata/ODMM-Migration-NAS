"""Headless regression tests for Windows Compact presentation model."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_windows_view_model import build_jobs_view


class WindowsViewModelTests(unittest.TestCase):
    def test_empty_dashboard_has_page(self):
        result = build_jobs_view([], "", "ALL", "id", False, 0, 200)
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["page"], 0)
        self.assertEqual(result["pages"], 1)
        self.assertIn("Total :", result["summary"])

    def test_view_does_not_mutate_rows(self):
        rows = [{"id": "a", "status": "RUNNING"}, {"id": "b", "status": "FAILED"}]
        original = [dict(x) for x in rows]
        result = build_jobs_view(rows, "", "ALL", "id", False, 0, 1, {"a"})
        self.assertEqual(rows, original)
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["pages"], 2)
        self.assertEqual(result["rows"][0]["id"], "a")
        self.assertTrue(result["rows"][0]["selected"])

    def test_unsupported_sort_column_rejected(self):
        with self.assertRaises(ValueError):
            build_jobs_view([], "", "ALL", "secret", False, 0, 200)


if __name__ == "__main__":
    unittest.main()
