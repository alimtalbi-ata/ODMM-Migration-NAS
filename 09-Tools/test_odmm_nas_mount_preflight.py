"""Negative qualification checks for NAS mount preflight."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from odmm_nas_mount_preflight import assess_mount, find_mount, matches_expected_type


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



class MountInfoParserTests(unittest.TestCase):
    def test_selects_deepest_mount_not_a_path_prefix(self):
        info = (
            "20 1 0:1 / / rw - ext4 /dev/root rw\n"
            "21 20 0:2 / /mnt/nas rw - cifs //server/share rw,vers=3.1.1\n"
            "22 20 0:3 / /mnt/nas-backup rw - nfs server:/backup rw,vers=3\n"
        )
        found = find_mount("/mnt/nas/folder", info)
        self.assertEqual(found["filesystem_type"], "cifs")
        self.assertEqual(found["mountpoint"], "/mnt/nas")

    def test_decodes_escaped_space_in_mountpoint(self):
        info = "20 1 0:2 / /mnt/nas\\040share rw - cifs //server/share rw,vers=3.1.1\n"
        found = find_mount("/mnt/nas share/subdir", info)
        self.assertEqual(found["mountpoint"], "/mnt/nas share")
        self.assertEqual(found["filesystem_type"], "cifs")

    def test_nfs4_super_option_is_distinguished_from_nfs3(self):
        nfs4 = "20 1 0:2 / /mnt/nfs rw - nfs server:/export rw,vers=4.1\n"
        nfs3 = "20 1 0:2 / /mnt/nfs rw - nfs server:/export rw,vers=3\n"
        self.assertIn("vers=4.1", find_mount("/mnt/nfs", nfs4)["super_options"])
        self.assertIn("vers=3", find_mount("/mnt/nfs", nfs3)["super_options"])

    def test_expected_protocol_version_matching_is_strict(self):
        nfs3 = {"filesystem_type": "nfs", "super_options": ["rw", "vers=3"]}
        nfs41 = {"filesystem_type": "nfs", "super_options": ["rw", "vers=4.1"]}
        cifs = {"filesystem_type": "cifs", "super_options": ["rw", "vers=3.1.1"]}
        self.assertTrue(matches_expected_type(nfs3, "nfs"))
        self.assertFalse(matches_expected_type(nfs41, "nfs"))
        self.assertTrue(matches_expected_type(nfs41, "nfs4"))
        self.assertFalse(matches_expected_type(nfs3, "nfs4"))
        self.assertTrue(matches_expected_type(cifs, "cifs"))
        self.assertFalse(matches_expected_type(cifs, "nfs4"))

    def test_assessment_identifies_expected_cifs_but_never_qualifies_acl(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            mountinfo = f"20 1 0:2 / {d} rw - cifs //nas/share rw,vers=3.1.1\n"
            report = assess_mount(d, "cifs", mountinfo_text=mountinfo)
            self.assertEqual(report["status"], "MOUNT_IDENTIFIED")
            self.assertEqual(report["filesystem_type"], "cifs")
            self.assertFalse(report["acl_qualified"])
            self.assertFalse(report["authorizes_migration"])
            self.assertEqual(report["reason"], "ACL_AND_IDENTITY_TESTS_STILL_REQUIRED")

    def test_assessment_rejects_nfs4_when_nfs3_expected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            mountinfo = f"20 1 0:2 / {d} rw - nfs server:/export rw,vers=4.1\n"
            report = assess_mount(d, "nfs", mountinfo_text=mountinfo)
            self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertEqual(report["reason"], "FILESYSTEM_TYPE_MISMATCH")
            self.assertFalse(report["authorizes_migration"])

    def test_assessment_identifies_nfs4_only_when_version_matches(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            mountinfo = f"20 1 0:2 / {d} rw - nfs server:/export rw,vers=4.1\n"
            report = assess_mount(d, "nfs4", mountinfo_text=mountinfo)
            self.assertEqual(report["status"], "MOUNT_IDENTIFIED")
            self.assertFalse(report["acl_qualified"])
            self.assertFalse(report["authorizes_migration"])

if __name__ == "__main__":
    unittest.main()
