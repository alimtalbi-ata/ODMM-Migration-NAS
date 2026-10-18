"""OIDC alert and retention regression; Author: Abdelhalim Talbi."""
import sqlite3,tempfile,unittest
from pathlib import Path
from odmm_oidc_alerts_v1997 import reconcile,history
class AlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/"history.sqlite"
        with sqlite3.connect(self.db) as c:
            c.execute("CREATE TABLE oidc_observations(id INTEGER PRIMARY KEY,observed_utc TEXT,state TEXT,discovery_jwks_ok INTEGER,latency_ms REAL)")
    def add(self,*states):
        with sqlite3.connect(self.db) as c:
            c.executemany("INSERT INTO oidc_observations(observed_utc,state,discovery_jwks_ok,latency_ms) VALUES('now',?,1,1.0)",[(s,) for s in states])
    def test_transition(self):
        self.add("AVAILABLE","DEGRADED","UNAVAILABLE","RECOVERING","AVAILABLE")
        self.assertEqual([e['event'] for e in reconcile(self.db)['new_events']],["OIDC_DEGRADED","OIDC_OUTAGE"])
    def test_recovery_direct(self):
        self.add("AVAILABLE","UNAVAILABLE","AVAILABLE")
        self.assertEqual([e['event'] for e in reconcile(self.db)['new_events']],["OIDC_DEGRADED","OIDC_RECOVERED"])
    def test_idempotent(self):
        self.add("AVAILABLE","DEGRADED")
        reconcile(self.db)
        self.assertEqual(reconcile(self.db)['new_events'],[])
        self.assertEqual(len(history(self.db)),1)
    def test_incremental(self):
        self.add("AVAILABLE","DEGRADED")
        reconcile(self.db);self.add("AVAILABLE")
        self.assertEqual(reconcile(self.db)['new_events'][0]['event'],"OIDC_RECOVERED")
    def test_retention(self):
        self.add(*(["AVAILABLE"]*25))
        reconcile(self.db,retain=10)
        with sqlite3.connect(self.db) as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM oidc_observations").fetchone()[0],10)
    def test_invalid_state_atomic(self):
        self.add("AVAILABLE","INVALID")
        with self.assertRaises(ValueError):reconcile(self.db)
        with sqlite3.connect(self.db) as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='oidc_alert_events'").fetchone()[0],0)
    def test_invalid_limit(self):
        with self.assertRaises(ValueError):history(self.db,limit=0)
    def test_no_database_creation(self):
        with self.assertRaises(FileNotFoundError):reconcile(Path(self.tmp.name)/"missing.sqlite")
