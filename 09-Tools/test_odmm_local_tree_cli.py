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
