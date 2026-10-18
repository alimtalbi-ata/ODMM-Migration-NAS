"""V200.0 audit and recovery regression. Author: Abdelhalim Talbi."""
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from odmm_oidc_sqlite_audit_v2000 import audit_tree,check_database
from odmm_oidc_health_history_v1995 import ingest,snapshot
from odmm_oidc_alerts_v1997 import reconcile,history

class AuditV2000(unittest.TestCase):
    def test_source_inventory(self):
        report=audit_tree(Path(__file__).parent)
        self.assertGreaterEqual(len(report["modules"]),2)
        self.assertFalse(report["native_engine_modified"])
    def test_missing_db_does_not_create(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"missing.sqlite"
            with self.assertRaises(FileNotFoundError):check_database(p)
            self.assertFalse(p.exists())
    def test_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"data.sqlite"
            with sqlite3.connect(p) as db:db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            self.assertTrue(check_database(p)["pass"])
    def test_recovery_after_process_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"history.sqlite"; report=Path(tmp)/"report.json"
            report.write_text(json.dumps({"checks":[{"state":"DEGRADED","discovery_jwks_ok":False,"latency_ms":15}]}))
            ingest(p,report)
            code = 'import sqlite3,sys; d=sqlite3.connect(sys.argv[1]); d.execute(\'BEGIN IMMEDIATE\'); d.execute("INSERT INTO oidc_observations(observed_utc,state,discovery_jwks_ok,latency_ms) VALUES (?,?,?,?)", (\'x\',\'AVAILABLE\',1,1)); sys.exit(0)'
            subprocess.run([sys.executable,"-c",code,str(p)],check=True)
            self.assertEqual(snapshot(p)["count"],1)
            self.assertEqual(reconcile(p)["processed"],1)
            self.assertEqual(len(history(p)),1)
            self.assertTrue(check_database(p)["pass"])
    def test_invalid_batch_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"history.sqlite"; report=Path(tmp)/"report.json"
            report.write_text(json.dumps({"checks":[{"state":"AVAILABLE","discovery_jwks_ok":True,"latency_ms":1}]}))
            ingest(p,report)
            report.write_text(json.dumps({"checks":[{"state":"AVAILABLE","discovery_jwks_ok":True,"latency_ms":1},{"state":"INVALID","discovery_jwks_ok":True,"latency_ms":1}]}))
            with self.assertRaises(ValueError):ingest(p,report)
            self.assertEqual(snapshot(p)["count"],1)
if __name__=="__main__":unittest.main()
