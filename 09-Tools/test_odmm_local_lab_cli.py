"""Subprocess acceptance test for the explicit ODMM local-lab CLI."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CLI = Path(__file__).resolve().parent / "odmm_local_lab_cli.py"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX only")
class LocalLabCliAcceptance(unittest.TestCase):
    def test_copy_and_refuse_overwrite_and_journal_reuse(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, target, journal = root / "source", root / "target", root / "journal.sqlite"
            content = os.urandom(32768)
            source.write_bytes(content)
            source.chmod(0o640)
            cmd = [sys.executable, str(CLI), "--source", str(source),
                   "--target", str(target), "--journal", str(journal),
                   "--ack-local-lab-only"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["state"], "VERIFIED")
            self.assertEqual(target.read_bytes(), content)
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)
            again = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(target.read_bytes(), content)

    def test_identical_existing_target_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, target, journal = root / "source", root / "target", root / "journal.sqlite"
            content = os.urandom(4096)
            source.write_bytes(content)
            target.write_bytes(content)
            before = target.stat()
            result = subprocess.run(
                [sys.executable, str(CLI), "--source", str(source),
                 "--target", str(target), "--journal", str(journal),
                 "--ack-local-lab-only"], capture_output=True, text=True, timeout=30)
            after = target.stat()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_bytes(), content)
            self.assertEqual((before.st_ino, before.st_mtime_ns, before.st_mode),
                             (after.st_ino, after.st_mtime_ns, after.st_mode))
            self.assertFalse(journal.exists())

    def test_target_symlink_refused_without_touching_external_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, external = root / "source", root / "external"
            source.write_bytes(b"source")
            external.write_bytes(b"protected")
            target = root / "target"
            target.symlink_to(external)
            journal = root / "journal.sqlite"
            result = subprocess.run(
                [sys.executable, str(CLI), "--source", str(source),
                 "--target", str(target), "--journal", str(journal),
                 "--ack-local-lab-only"], capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(external.read_bytes(), b"protected")
            self.assertTrue(target.is_symlink())
            self.assertFalse(journal.exists())

    def test_explicit_lab_acknowledgement_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.write_bytes(b"safe")
            result = subprocess.run(
                [sys.executable, str(CLI), "--source", str(source),
                 "--target", str(root / "target"),
                 "--journal", str(root / "journal.sqlite")],
                capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "target").exists())
            self.assertFalse((root / "journal.sqlite").exists())


if __name__ == "__main__":
    unittest.main()
