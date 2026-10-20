"""Uncertain local lab reconciliation must never mutate intent state."""
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lease_registry import initialize as init_leases, claim
from odmm_linux_datamover_intents import initialize, quarantine_unfinished, unresolved
from odmm_linux_lab_pipeline import run_lab_copy, LabPipelineError
from odmm_linux_lab_reconciliation import inspect_uncertain, ReconciliationError

class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.src, self.dst = root / "source", root / "target"
        self.src.write_bytes(b"evidence" * 1024)
        self.db = sqlite3.connect(str(root / "state.db"), isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        init_leases(self.db)
        initialize(self.db)
        self.token = claim(self.db, "task", "worker", 100, now=100)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _crash(self, fault):
        with self.assertRaises(LabPipelineError):
            run_lab_copy(self.db, intent_id="i", task_id="task", owner="worker",
                         token=self.token, source=self.src, target=self.dst,
                         now=101, fault_at=fault)
        self.assertEqual(quarantine_unfinished(self.db, now=102), 1)

    def test_absent_target_requires_review(self):
        self._crash("after_intent")
        result = inspect_uncertain(self.db, "i", self.src, self.dst)
        self.assertEqual(result["reason"], "TARGET_ABSENT")
        self.assertEqual(result["decision"], "MANUAL_REVIEW_REQUIRED")
        self.assertEqual(unresolved(self.db)[0][-1], "UNCERTAIN")

    def test_complete_bytes_without_mode_restore_stays_uncertain(self):
        self._crash("after_copy_fsync")
        result = inspect_uncertain(self.db, "i", self.src, self.dst)
        self.assertFalse(result["content_verified"])
        self.assertEqual(result["reason"], "POSIX_MODE_MISMATCH")
        self.assertEqual(self.dst.read_bytes(), self.src.read_bytes())
        self.assertFalse(result["nas_acl_qualified"])
        self.assertEqual(unresolved(self.db)[0][-1], "UNCERTAIN")

    def test_partial_target_rejected(self):
        self._crash("during_copy")
        result = inspect_uncertain(self.db, "i", self.src, self.dst)
        self.assertFalse(result["content_verified"])
        self.assertEqual(result["reason"], "CONTENT_MISMATCH")

if __name__ == "__main__":
    unittest.main()
