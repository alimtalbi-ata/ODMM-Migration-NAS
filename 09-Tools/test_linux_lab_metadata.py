"""Regression tests for local read-only POSIX metadata inspection."""
import sys
import os
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
            stamp = src.stat()
            os.utime(dst, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            result = inspect_metadata(src, dst)
            self.assertEqual(result["status"], "LOCAL_METADATA_MATCH")
            self.assertFalse(result["nas_acl_qualified"])
            self.assertFalse(result["authorizes_resume"])

    def test_mode_mismatch_requires_review(self):
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "src", Path(d) / "dst"
            src.write_bytes(b"same")
            dst.write_bytes(b"same")
            stamp = src.stat()
            os.utime(dst, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
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

    def test_xattr_mismatch_requires_review_when_supported(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "src", Path(d) / "dst"
            src.write_bytes(b"same")
            dst.write_bytes(b"same")
            stamp = src.stat()
            os.utime(dst, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            try:
                os.setxattr(src, "user.odmm_probe", b"source")
                os.setxattr(dst, "user.odmm_probe", b"target")
            except OSError as exc:
                self.skipTest("user xattrs unavailable: " + str(exc))
            result = inspect_metadata(src, dst)
            self.assertEqual(result["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertIn("xattrs_hex", result["differences"])
            self.assertFalse(result["authorizes_resume"])

    def test_xattr_match_is_not_nas_acl_qualification(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "src", Path(d) / "dst"
            src.write_bytes(b"same")
            dst.write_bytes(b"same")
            stamp = src.stat()
            os.utime(dst, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            try:
                os.setxattr(src, "user.odmm_probe", b"equal")
                os.setxattr(dst, "user.odmm_probe", b"equal")
            except OSError as exc:
                self.skipTest("user xattrs unavailable: " + str(exc))
            result = inspect_metadata(src, dst)
            self.assertEqual(result["status"], "LOCAL_METADATA_MATCH")
            self.assertFalse(result["nas_acl_qualified"])
            self.assertFalse(result["authorizes_resume"])


if __name__ == "__main__":
    unittest.main()
