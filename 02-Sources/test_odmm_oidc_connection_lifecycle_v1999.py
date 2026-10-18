"""ODMM V199.9: SQLite connections are closed after normal and exceptional paths."""
import gc
import json
import sqlite3
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch
import odmm_oidc_health_history_v1995 as module

class ConnectionLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/"history.sqlite"
        self.report=Path(self.tmp.name)/"report.json"
        self.report.write_text(json.dumps({"checks":[{"state":"AVAILABLE","discovery_jwks_ok":True,"latency_ms":2.5}]}))

    def test_ingest_and_snapshot_no_resource_warning(self):
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always", ResourceWarning)
            self.assertEqual(module.ingest(self.db,self.report),1)
            self.assertEqual(module.snapshot(self.db)["count"],1)
            gc.collect()
        self.assertFalse([w for w in recorded if issubclass(w.category,ResourceWarning)],recorded)

    def test_ingest_connection_closes_on_success(self):
        connections=[]
        original=sqlite3.connect
        def tracking(*args,**kwargs):
            conn=original(*args,**kwargs);connections.append(conn);return conn
        with patch.object(module.sqlite3,"connect",side_effect=tracking):
            module.ingest(self.db,self.report)
            module.snapshot(self.db)
        self.assertEqual(len(connections),2)
        for conn in connections:
            with self.assertRaises(sqlite3.ProgrammingError):conn.execute("SELECT 1")

    def test_ingest_rolls_back_on_insert_failure_and_closes(self):
        module.ingest(self.db,self.report)
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TRIGGER reject_oidc BEFORE INSERT ON oidc_observations BEGIN SELECT RAISE(ABORT,'blocked'); END")
        with self.assertRaises(sqlite3.IntegrityError):module.ingest(self.db,self.report)
        self.assertEqual(module.snapshot(self.db)["count"],1)

    def test_invalid_input_does_not_create_database(self):
        self.report.write_text('{"checks":[{"state":"INVALID"}]}')
        with self.assertRaises(ValueError):module.ingest(self.db,self.report)
        self.assertFalse(self.db.exists())

if __name__=="__main__":unittest.main()
