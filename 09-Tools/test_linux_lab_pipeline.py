"""Local lab pipeline end-to-end and unsafe-retry regression tests."""
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lease_registry import initialize as init_leases, claim
from odmm_linux_datamover_intents import initialize, quarantine_unfinished, unresolved
from odmm_linux_lab_pipeline import run_lab_copy, LabPipelineError

class LabPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = sqlite3.connect(str(self.root / "registry.db"), isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        init_leases(self.db)
        initialize(self.db)
        self.token = claim(self.db, "task", "mover", 100, now=100)
        self.src = self.root / "source.bin"
        self.dst = self.root / "target.bin"
        self.src.write_bytes(b"local-lab" * 10000)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_complete_local_copy_verified(self):
        result = run_lab_copy(self.db, intent_id="i1", task_id="task", owner="mover",
                              token=self.token, source=self.src, target=self.dst, now=101)
        self.assertEqual(result["state"], "VERIFIED")
        self.assertEqual(self.src.read_bytes(), self.dst.read_bytes())
        self.assertEqual(unresolved(self.db), [])
        self.assertFalse(result["production_nas_qualified"])

    def test_existing_target_refused_without_intent(self):
        self.dst.write_bytes(b"keep")
        with self.assertRaisesRegex(LabPipelineError, "TARGET_ALREADY_EXISTS"):
            run_lab_copy(self.db, intent_id="i1", task_id="task", owner="mover",
                         token=self.token, source=self.src, target=self.dst, now=101)
        self.assertEqual(self.dst.read_bytes(), b"keep")
        self.assertEqual(unresolved(self.db), [])

    def test_retry_refused_after_success(self):
        run_lab_copy(self.db, intent_id="i1", task_id="task", owner="mover",
                     token=self.token, source=self.src, target=self.dst, now=101)
        with self.assertRaisesRegex(LabPipelineError, "TARGET_ALREADY_EXISTS"):
            run_lab_copy(self.db, intent_id="i1", task_id="task", owner="mover",
                         token=self.token, source=self.src, target=self.dst, now=102)

if __name__ == "__main__":
    unittest.main()
