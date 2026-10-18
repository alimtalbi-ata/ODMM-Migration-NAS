import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from odmm_oidc_health_history_v1995 import ingest,snapshot
class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/"health.sqlite"
        self.report=Path(self.tmp.name)/"health.json"
    def write(self,checks):self.report.write_text(json.dumps({"checks":checks}))
    def test_roundtrip(self):
        self.write([{"state":"AVAILABLE","discovery_jwks_ok":True,"latency_ms":12.5}])
        self.assertEqual(ingest(self.db,self.report),1)
        self.assertEqual(snapshot(self.db)["observations"][0]["state"],"AVAILABLE")
        self.assertEqual(snapshot(self.db)["migration_engine_status"],"NOT_MEASURED")
    def test_invalid_state_does_not_write(self):
        self.write([{"state":"AVAILABLE","discovery_jwks_ok":True,"latency_ms":1},{"state":"INVALID","discovery_jwks_ok":True,"latency_ms":1}])
        with self.assertRaises(ValueError):ingest(self.db,self.report)
        self.assertFalse(self.db.exists())
    def test_negative_latency_rejected(self):
        self.write([{"state":"AVAILABLE","discovery_jwks_ok":True,"latency_ms":-1}])
        with self.assertRaises(ValueError):ingest(self.db,self.report)
    def test_limit(self):
        self.write([{"state":"DEGRADED","discovery_jwks_ok":False,"latency_ms":1}]*3)
        ingest(self.db,self.report)
        self.assertEqual(snapshot(self.db,2)["count"],2)
    def test_invalid_limit(self):
        with self.assertRaises(ValueError):snapshot(self.db,1001)
