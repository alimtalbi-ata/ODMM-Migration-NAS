"""Headless regression checks for read-only SQLite registry auditing."""
import importlib.util
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("VERIFY-SQLITE-REGISTRY-CONTRACT.py")
spec = importlib.util.spec_from_file_location("registry_contract", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RegistryAuditTests(unittest.TestCase):
    def test_missing_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "missing.sqlite"
            with self.assertRaisesRegex(ValueError, "REGISTRY_NOT_FOUND"):
                module.inspect_registry(path)
            self.assertFalse(path.exists())

    def test_wal_registry_integrity(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "registry.sqlite"
            with closing(sqlite3.connect(path)) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA synchronous=FULL")
                db.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY)")
                db.execute("INSERT INTO jobs VALUES ('job-1')")
                db.commit()
            result = module.inspect_registry(path)
            self.assertEqual(result["integrity_check"], "ok")
            self.assertEqual(result["quick_check"], "ok")
            self.assertEqual(result["journal_mode"], "wal")
            self.assertTrue(result["passed"])

    def test_pending_intent_is_reported_without_reconciliation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "registry.sqlite"
            with closing(sqlite3.connect(path)) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("CREATE TABLE files (path TEXT PRIMARY KEY)")
                db.execute("CREATE TABLE intents (path TEXT PRIMARY KEY)")
                db.execute("INSERT INTO intents VALUES ('unfinished')")
                db.commit()
            result = module.inspect_registry(path)
            self.assertEqual(result["pending_intents"], 1)
            self.assertEqual(result["verified_files"], 0)
            self.assertTrue(result["reconciliation_required"])
            self.assertTrue(result["native_schema_detected"])
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM intents").fetchone()[0], 1)

    def test_corrupt_registry_not_reported_as_valid(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "registry.sqlite"
            path.write_bytes(b"invalid database")
            with self.assertRaises(sqlite3.DatabaseError):
                module.inspect_registry(path)


if __name__ == "__main__":
    unittest.main()
