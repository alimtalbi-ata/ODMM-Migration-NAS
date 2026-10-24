"""Subprocess acceptance for the guarded local tree copy CLI."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CLI = Path(__file__).resolve().parent / "odmm_local_tree_cli.py"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX only")
class TreeCliAcceptance(unittest.TestCase):
    def run_cli(self, source, target):
        return subprocess.run(
            [sys.executable, str(CLI), "--source", str(source),
             "--target", str(target), "--ack-local-lab-only"],
            capture_output=True, text=True, timeout=30)

    def test_nested_tree_files_permissions_and_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            (source / "nested" / "emptydir").mkdir(parents=True)
            (source / "root.bin").write_bytes(b"root" * 1024)
            (source / "nested" / "data.txt").write_text("ODMM arbre")
            (source / "nested").chmod(0o750)
            (source / "nested" / "data.txt").chmod(0o640)
            result = self.run_cli(source, target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["files_copied"], 2)
            self.assertEqual(json.loads(result.stdout)["files_verified"], 2)
            self.assertEqual((target / "root.bin").read_bytes(), (source / "root.bin").read_bytes())
            self.assertEqual((target / "nested" / "data.txt").read_bytes(),
                             (source / "nested" / "data.txt").read_bytes())
            self.assertTrue((target / "nested" / "emptydir").is_dir())
            self.assertEqual((target / "nested").stat().st_mode & 0o777, 0o750)
            self.assertEqual((target / "nested" / "data.txt").stat().st_mode & 0o777, 0o640)
            self.assertTrue((target / ".odmm-local-journal.sqlite").is_file())
            self.assertNotEqual(self.run_cli(source, target).returncode, 0)

    def test_symlink_rejected_before_target_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            (source / "link").symlink_to(root)
            result = self.run_cli(source, target)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(target.exists())

    def test_hardlink_rejected_before_target_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            first = source / "first.bin"
            first.write_bytes(b"hardlink content")
            (source / "second.bin").hardlink_to(first)
            result = self.run_cli(source, target)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("HARDLINK_UNSUPPORTED", [item["code"] for item in json.loads(result.stderr)["findings"]])
            self.assertFalse(target.exists())

    def test_xattr_rejected_before_target_creation_when_supported(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            path = source / "data.bin"
            path.write_bytes(b"metadata")
            try:
                os.setxattr(path, "user.odmm_test", b"preserve-me")
            except (OSError, AttributeError):
                self.skipTest("user xattrs unavailable on test filesystem")
            result = self.run_cli(source, target)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("XATTR_OR_ACL_UNSUPPORTED", [item["code"] for item in json.loads(result.stderr)["findings"]])
            self.assertFalse(target.exists())

    def test_preflight_blocks_unsupported_metadata_without_target(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            data = source / "file"
            data.write_bytes(b"must-not-be-copied")
            try:
                os.setxattr(data, "user.odmm_guard", b"acl-metadata")
            except (OSError, AttributeError):
                self.skipTest("xattrs unavailable on filesystem")
            result = self.run_cli(source, target)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stderr)
            self.assertEqual(report["state"], "BLOCKED_BY_PREFLIGHT")
            self.assertFalse(report["target_created"])
            self.assertFalse(target.exists())

    def test_tree_copy_reports_verified_file_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            for index in range(5):
                (source / f"file-{index}.bin").write_bytes(bytes([index]) * 8192)
            result = self.run_cli(source, target)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["files_copied"], 5)
            self.assertEqual(report["files_verified"], 5)
            self.assertFalse(report["nas_migration_qualified"])

    def test_source_fingerprint_detects_same_size_rewrite(self):
        import importlib.util
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / "file.bin"
            file.write_bytes(b"original")
            spec = importlib.util.spec_from_file_location("odmm_tree_cli", TOOL)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            before = module.source_fingerprint(file)
            file.write_bytes(b"modified")
            os.utime(file, ns=(file.stat().st_atime_ns, before[3]))
            self.assertNotEqual(before, module.source_fingerprint(file))

    def test_source_target_overlap_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            result = self.run_cli(source, source / "target")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((source / "target").exists())


if __name__ == "__main__":
    unittest.main()
