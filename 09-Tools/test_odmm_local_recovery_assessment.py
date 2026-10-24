"""Acceptance for combined read-only SQLite and tree recovery assessment."""
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "odmm_local_recovery_assessment.py"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux only")
class CombinedRecoveryTests(unittest.TestCase):
    def test_unresolved_intent_and_missing_file_are_both_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            src.mkdir()
            dst.mkdir()
            (src / "data").write_bytes(b"important")
            with sqlite3.connect(journal) as db:
                db.execute("CREATE TABLE odmm_datamover_intents (intent_id TEXT, task_id TEXT, state TEXT)")
                db.execute("INSERT INTO odmm_datamover_intents VALUES ('i1','task1','IN_FLIGHT')")
            before = journal.read_bytes()
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertEqual(report["tree_counts"]["missing_files"], 1)
            self.assertEqual(report["unresolved_intents"][0]["state"], "IN_FLIGHT")
            self.assertEqual(report["mapping_limit"], "NO_DURABLE_TASK_TO_PATH_MAPPING")
            self.assertFalse(report["authorizes_resume"])
            self.assertEqual(journal.read_bytes(), before)
            self.assertFalse((dst / "data").exists())


if __name__ == "__main__":
    unittest.main()
