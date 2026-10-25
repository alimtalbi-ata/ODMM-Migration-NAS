"""Capability-report acceptance and explicit NAS qualification gate."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "odmm_capabilities.py"


class CapabilitiesTests(unittest.TestCase):
    def run_report(self, *extra):
        return subprocess.run([sys.executable, str(TOOL), *extra],
                              capture_output=True, text=True, timeout=30)

    def test_local_evidence_and_nas_unqualified(self):
        result = self.run_report()
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertFalse(data["production_nas_qualified"])
        self.assertEqual(data["capabilities"]["local_posix_directory_tree_copy"]["status"], "lab_qualified")
        self.assertEqual(data["capabilities"]["nfs_v3_v4_migration"]["status"], "not_qualified")
        self.assertEqual(data["capabilities"]["smb_ntfs_acl_migration"]["status"], "not_qualified")

    def test_required_nas_capability_fails_closed(self):
        for capability in ("nfs_v3_v4_migration", "smb_ntfs_acl_migration",
                           "production_recovery_resume"):
            with self.subTest(capability=capability):
                result = self.run_report("--require", capability)
                self.assertEqual(result.returncode, 2)
        self.assertEqual(
            self.run_report("--require", "local_posix_directory_tree_copy").returncode, 0)


if __name__ == "__main__":
    unittest.main()
