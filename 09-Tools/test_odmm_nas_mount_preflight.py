"""Negative qualification checks for NAS mount preflight."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from odmm_nas_mount_preflight import assess_mount


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux only")
class NasMountPreflightTests(unittest.TestCase):
    def test_local_directory_cannot_be_reported_as_nfs(self):
        report = assess_mount("/tmp", "nfs")
        self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
        self.assertFalse(report["acl_qualified"])
        self.assertFalse(report["authorizes_migration"])

    def test_nonexistent_mount_fails_closed(self):
        report = assess_mount("/odmm-qualification-path-that-does-not-exist", "cifs")
        self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
        self.assertFalse(report["authorizes_migration"])

    def test_invalid_type_fails_closed(self):
        report = assess_mount("/tmp", "ext4")
        self.assertEqual(report["reason"], "UNSUPPORTED_EXPECTED_TYPE")


if __name__ == "__main__":
    unittest.main()
