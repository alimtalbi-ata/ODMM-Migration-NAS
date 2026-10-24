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
            self.assertIn("xattrs_sha256", result["differences"])
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

    def test_concurrent_xattr_value_change_is_rejected(self):
        import unittest.mock
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "src", Path(d) / "dst"
            src.write_bytes(b"same")
            dst.write_bytes(b"same")
            stamp = src.stat()
            os.utime(dst, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            try:
                os.setxattr(src, "user.odmm_probe", b"before")
                os.setxattr(dst, "user.odmm_probe", b"before")
            except OSError as exc:
                self.skipTest("user xattrs unavailable: " + str(exc))
            original = os.getxattr
            calls = {"count": 0}

            def changing_getxattr(fd, name, *args, **kwargs):
                if name == "user.odmm_probe":
                    calls["count"] += 1
                    if calls["count"] == 2:
                        return b"after"
                return original(fd, name, *args, **kwargs)

            with unittest.mock.patch("odmm_linux_lab_metadata.os.getxattr",
                                     side_effect=changing_getxattr):
                result = inspect_metadata(src, dst)
            self.assertEqual(result["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertFalse(result["authorizes_resume"])

    def test_pathname_replacement_during_xattr_read_is_rejected(self):
        import unittest.mock
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "src", Path(d) / "dst"
            src.write_bytes(b"same")
            dst.write_bytes(b"same")
            stamp = src.stat()
            os.utime(dst, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            try:
                os.setxattr(src, "user.odmm_probe", b"value")
                os.setxattr(dst, "user.odmm_probe", b"value")
            except OSError as exc:
                self.skipTest("user xattrs unavailable: " + str(exc))
            original = os.getxattr
            switched = {"done": False}

            def replacing_getxattr(fd, name, *args, **kwargs):
                if not switched["done"]:
                    switched["done"] = True
                    replacement = Path(d) / "replacement"
                    replacement.write_bytes(b"same")
                    os.replace(replacement, src)
                return original(fd, name, *args, **kwargs)

            with unittest.mock.patch("odmm_linux_lab_metadata.os.getxattr",
                                     side_effect=replacing_getxattr):
                result = inspect_metadata(src, dst)
            self.assertEqual(result["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertFalse(result["authorizes_resume"])

    def test_xattr_secret_not_exposed_in_report(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            src, dst = Path(d) / "src", Path(d) / "dst"
            src.write_bytes(b"same")
            dst.write_bytes(b"same")
            stamp = src.stat()
            os.utime(dst, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            secret = b"odmm-private-credential-test-value"
            try:
                os.setxattr(src, "user.odmm_probe", secret)
                os.setxattr(dst, "user.odmm_probe", b"different")
            except OSError as exc:
                self.skipTest("user xattrs unavailable: " + str(exc))
            result = inspect_metadata(src, dst)
            rendered = json.dumps(result)
            self.assertEqual(result["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertNotIn(secret.decode(), rendered)
            self.assertNotIn(secret.hex(), rendered)
            self.assertIn("sha256", rendered)
            self.assertFalse(result["authorizes_resume"])


if __name__ == "__main__":
    unittest.main()
