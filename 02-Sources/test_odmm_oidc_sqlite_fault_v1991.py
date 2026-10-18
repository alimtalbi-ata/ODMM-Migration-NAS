"""SQLite OIDC failure injection and resource lifecycle regression.
Author: Abdelhalim Talbi.
"""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from odmm_oidc_session_store import SQLiteOIDCStore
from odmm_operations_security import Principal

class SQLiteFaultTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/"sessions.sqlite"
        self.store=SQLiteOIDCStore(self.path,clock=lambda:1000.0)
        self.principal=Principal("alice",frozenset({"reader"}),verified=True)
    def test_repeated_queries_release_sqlite_handles(self):
        self.store.put_session("sid",self.principal,1100)
        for _ in range(100):
            self.assertIsNotNone(self.store.get_session("sid"))
        with sqlite3.connect(self.path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("ROLLBACK")
    def test_database_locked_fails_closed(self):
        self.store.put_session("sid",self.principal,1100)
        self.store.bind_csrf("sid","csrf")
        with sqlite3.connect(self.path,timeout=0.1,isolation_level=None) as blocker:
            blocker.execute("BEGIN EXCLUSIVE")
            try:
                with patch.object(self.store,"_connect",side_effect=sqlite3.OperationalError("database is locked")):
                    with self.assertRaises(sqlite3.OperationalError):
                        self.store.verify_csrf("sid","csrf")
            finally:
                blocker.execute("ROLLBACK")
        self.assertTrue(self.store.verify_csrf("sid","csrf"))
    def test_connect_setup_failure_closes_connection(self):
        class FailingConnection:
            closed=False
            def execute(self,sql): raise sqlite3.OperationalError("injected pragma failure")
            def close(self): self.closed=True
        fake=FailingConnection()
        with patch("odmm_oidc_session_store.sqlite3.connect",return_value=fake):
            with self.assertRaises(sqlite3.OperationalError): self.store._connect()
        self.assertTrue(fake.closed)
    def test_expired_session_fails_closed(self):
        self.store.put_session("sid",self.principal,999)
        self.store.bind_csrf("sid","csrf")
        self.assertIsNone(self.store.get_session("sid"))
        self.assertFalse(self.store.verify_csrf("sid","csrf"))
    def test_deleted_session_fails_closed(self):
        self.store.put_session("sid",self.principal,1100)
        self.store.bind_csrf("sid","csrf")
        self.store.delete_session("sid")
        self.assertFalse(self.store.verify_csrf("sid","csrf"))

if __name__=="__main__": unittest.main()
