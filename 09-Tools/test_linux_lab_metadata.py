"""Regression tests for local read-only POSIX metadata inspection."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lab_metadata import inspect_metadata


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux only")
class MetadataTests(unittest.TestCase):
    def test_equal_files_have_advisory_match(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "src", Path(d) / "dst"
            src.write_bytes(b"same")
            dst.write_bytes(b"same")
            result = inspect_metadata(src, dst)
            self.assertEqual(result["status"], "LOCAL_METADATA_MATCH")
            self.assertFalse(result["nas_acl_qualified"])
            self.assertFalse(result["authorizes_resume"])

    def test_mode_mismatch_requires_review(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "src", Path(d) / "dst"
            src.write_bytes(b"same")
            dst.write_bytes(b"same")
            src.chmod(0o600)
            dst.chmod(0o644)
            result = inspect_metadata(src, dst)
            self.assertEqual(result["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertIn("mode", result["differences"])

    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "src", Path(d) / "dst"
            src.write_bytes(b"same")
            dst.symlink_to(src)
            result = inspect_metadata(src, dst)
            self.assertEqual(result["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertFalse(result["authorizes_resume"])


if __name__ == "__main__":
    unittest.main()
