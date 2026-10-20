"""Single-registry fencing and crash/restart regression tests."""
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lease_registry import initialize, claim, renew, release, assert_current, guarded_registry_effect, LeaseConflict

class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "leases.db")
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        initialize(self.db)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_exclusive_claim_and_stale_fence(self):
        first = claim(self.db, "task1", "mover-a", 10, now=100)
        with self.assertRaisesRegex(LeaseConflict, "TASK_ALREADY_OWNED"):
            claim(self.db, "task1", "mover-b", 10, now=101)
        second = claim(self.db, "task1", "mover-b", 10, now=111)
        self.assertGreater(second, first)
        with self.assertRaisesRegex(LeaseConflict, "STALE_OR_EXPIRED"):
            renew(self.db, "task1", "mover-a", first, 10, now=112)
        self.assertEqual(second, renew(self.db, "task1", "mover-b", second, 10, now=112))

    def test_release_rejects_stale_token(self):
        token = claim(self.db, "task", "a", 20, now=100)
        with self.assertRaises(LeaseConflict):
            release(self.db, "task", "a", token + 1, now=101)
        release(self.db, "task", "a", token, now=101)
        with self.assertRaises(LeaseConflict):
            release(self.db, "task", "a", token, now=102)

    def test_restart_persists_fence(self):
        token = claim(self.db, "task", "a", 2, now=100)
        self.db.close()
        self.db = sqlite3.connect(self.path, isolation_level=None)
        initialize(self.db)
        self.assertGreater(claim(self.db, "task", "b", 2, now=103), token)

    def test_guarded_effect_commits_only_current_owner(self):
        self.db.execute("CREATE TABLE audit(value TEXT NOT NULL)")
        token = claim(self.db, "task", "a", 10, now=100)
        guarded_registry_effect(self.db, "task", "a", token,
                                lambda db: db.execute("INSERT INTO audit VALUES('accepted')"), now=101)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM audit").fetchone()[0], 1)
        with self.assertRaises(LeaseConflict):
            guarded_registry_effect(self.db, "task", "b", token,
                                    lambda db: db.execute("INSERT INTO audit VALUES('wrong')"), now=101)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM audit").fetchone()[0], 1)

    def test_guarded_effect_rollback_on_failure(self):
        self.db.execute("CREATE TABLE audit(value TEXT NOT NULL)")
        token = claim(self.db, "task", "a", 10, now=100)
        def failing(db):
            db.execute("INSERT INTO audit VALUES('rollback')")
            raise RuntimeError("intentional")
        with self.assertRaises(RuntimeError):
            guarded_registry_effect(self.db, "task", "a", token, failing, now=101)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM audit").fetchone()[0], 0)

    def test_guard_rejects_expired_token(self):
        token = claim(self.db, "task", "a", 10, now=100)
        with self.assertRaises(LeaseConflict):
            assert_current(self.db, "task", "a", token, now=110)

    def test_invalid_ttl_rejected(self):
        with self.assertRaises(ValueError):
            claim(self.db, "task", "a", True, now=100)

if __name__ == "__main__":
    unittest.main()
