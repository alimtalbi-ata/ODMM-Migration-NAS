"""Acceptance checks for read-only local POSIX recovery triage."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "odmm_local_tree_recovery_triage.py"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux only")
class RecoveryTriageTests(unittest.TestCase):
    def invoke(self, src, dst):
        return subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                               "--target", str(dst)], capture_output=True,
                              text=True, timeout=30)

    def test_matching_tree_does_not_modify_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / "src", Path(tmp) / "dst"
            src.mkdir()
            dst.mkdir()
            (src / "data").write_bytes(b"hello")
            (dst / "data").write_bytes(b"hello")
            before = (dst / "data").read_bytes()
            result = self.invoke(src, dst)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["counts"]["verified_files"], 1)
            self.assertFalse(report["authorizes_resume"])
            self.assertEqual((dst / "data").read_bytes(), before)

    def test_replaced_file_is_rejected_during_hash(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("recovery_triage", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "file"
            path.write_bytes(b"same")
            original = path.lstat()
            path.unlink()
            path.write_bytes(b"same")
            with self.assertRaisesRegex(RuntimeError, "FILE_CHANGED_BEFORE_HASH"):
                module.digest(path, original)

    def test_symlink_substitution_is_rejected(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("recovery_triage", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "file"
            path.write_bytes(b"same")
            original = path.lstat()
            path.unlink()
            path.symlink_to(Path(tmp) / "elsewhere")
            with self.assertRaises(OSError):
                module.digest(path, original)

    def test_root_mode_mismatch_requires_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / "src", Path(tmp) / "dst"
            src.mkdir(mode=0o700)
            dst.mkdir(mode=0o700)
            src.chmod(0o750)
            dst.chmod(0o700)
            result = self.invoke(src, dst)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertIn("ROOT_MODE_MISMATCH",
                          [item["code"] for item in report["findings"]])
            self.assertFalse(report["authorizes_resume"])

    def test_hardlinked_source_requires_review_even_if_bytes_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / "src", Path(tmp) / "dst"
            src.mkdir()
            dst.mkdir()
            (src / "data").write_bytes(b"same")
            (src / "alias").hardlink_to(src / "data")
            (dst / "data").write_bytes(b"same")
            (dst / "alias").write_bytes(b"same")
            result = self.invoke(src, dst)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertIn("UNSAFE_SOURCE_HARDLINK",
                          [finding["code"] for finding in report["findings"]])
            self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertFalse(report["authorizes_resume"])

    def test_missing_and_corrupted_files_require_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / "src", Path(tmp) / "dst"
            src.mkdir()
            dst.mkdir()
            (src / "missing").write_bytes(b"missing")
            (src / "changed").write_bytes(b"source")
            (dst / "changed").write_bytes(b"TARGET")
            result = self.invoke(src, dst)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["counts"]["missing_files"], 1)
            self.assertEqual(report["counts"]["mismatched_files"], 1)
            self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertFalse((dst / "missing").exists())


if __name__ == "__main__":
    unittest.main()
