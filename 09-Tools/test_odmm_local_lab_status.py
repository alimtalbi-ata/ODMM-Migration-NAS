"""Acceptance tests for local journal status command, including fail-closed behavior."""
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

STATUS = Path(__file__).resolve().parent / "odmm_local_lab_status.py"
COPY = Path(__file__).resolve().parent / "odmm_local_lab_cli.py"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX only")
class LocalStatusTests(unittest.TestCase):
    def test_completed_copy_visible_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, db = root / "source", root / "target", root / "journal.sqlite"
            src.write_bytes(b"real local lab copy")
            copy = subprocess.run(
                [sys.executable, str(COPY), "--source", str(src), "--target",
                 str(dst), "--journal", str(db), "--ack-local-lab-only"],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(copy.returncode, 0, copy.stderr)
            before = db.read_bytes()
            status = subprocess.run(
                [sys.executable, str(STATUS), "--journal", str(db)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(status.returncode, 0, status.stderr)
            doc = json.loads(status.stdout)
            self.assertEqual([r["state"] for r in doc["intents"]], ["VERIFIED"])
            self.assertFalse(doc["authorizes_resume"])
            self.assertEqual(db.read_bytes(), before)

    def test_missing_or_symlink_journal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real.sqlite"
            sqlite3.connect(real).close()
            link = root / "link.sqlite"
            link.symlink_to(real)
            for path in (link, root / "missing.sqlite"):
                result = subprocess.run(
                    [sys.executable, str(STATUS), "--journal", str(path)],
                    capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(json.loads(result.stderr)["authorizes_resume"])


if __name__ == "__main__":
    unittest.main()
