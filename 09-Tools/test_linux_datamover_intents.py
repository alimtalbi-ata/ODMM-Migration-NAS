"""Durable intent journal regression tests; no external NAS side effects."""
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lease_registry import initialize as init_leases, claim, LeaseConflict
from odmm_linux_datamover_intents import initialize, prepare, mark_in_flight, quarantine_unfinished, unresolved, IntentConflict

class IntentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "journal.db")
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        init_leases(self.db)
        initialize(self.db)
        self.token = claim(self.db, "task", "mover", 20, now=100)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_recovery_quarantines_in_flight(self):
        prepare(self.db, "intent", "task", "mover", self.token, {"path": "/example"}, now=101)
        mark_in_flight(self.db, "intent", "task", "mover", self.token, now=102)
        self.db.close()
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.assertEqual(quarantine_unfinished(self.db, now=103), 1)
        self.assertEqual(unresolved(self.db)[0][-1], "UNCERTAIN")
        with self.assertRaises(IntentConflict):
            mark_in_flight(self.db, "intent", "task", "mover", self.token, now=104)

    def test_idempotent_prepare_and_conflicting_payload(self):
        d1 = prepare(self.db, "intent", "task", "mover", self.token, {"a": 1}, now=101)
        self.assertEqual(d1, prepare(self.db, "intent", "task", "mover", self.token, {"a": 1}, now=102))
        with self.assertRaises(IntentConflict):
            prepare(self.db, "intent", "task", "mover", self.token, {"a": 2}, now=103)

    def test_stale_fence_blocks_intent(self):
        with self.assertRaises(LeaseConflict):
            prepare(self.db, "intent", "task", "mover", self.token + 1, {"a": 1}, now=101)
        self.assertEqual(unresolved(self.db), [])

    def test_prepared_not_quarantined(self):
        prepare(self.db, "intent", "task", "mover", self.token, {}, now=101)
        self.assertEqual(quarantine_unfinished(self.db, now=102), 0)

if __name__ == "__main__":
    unittest.main()
