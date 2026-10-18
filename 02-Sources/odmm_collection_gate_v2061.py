"""V206.1 transactional multi-worker collection rate gate. Auteur: Abdelhalim Talbi.

SQLite BEGIN IMMEDIATE serializes independent workers; no process-local lock required.
"""
import hashlib
import sqlite3
import time
from urllib.parse import urlsplit
import hmac

class TransactionalSecurityGate:
    def __init__(self, db_path, *, interval=60, max_requests=3, clock=None):
        if interval <= 0 or max_requests < 1: raise ValueError('INVALID_LIMITS')
        self.db_path=str(db_path)
        self.interval=interval
        self.max_requests=max_requests
        self.clock=clock or time.time
        with self._connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at REAL NOT NULL, actor_hash TEXT NOT NULL, event TEXT NOT NULL, outcome TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS rate (actor_hash TEXT NOT NULL, at REAL NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_rate_actor_time ON rate(actor_hash,at)')
    def _connect(self):
        db=sqlite3.connect(self.db_path,timeout=10)
        db.execute('PRAGMA busy_timeout=10000')
        return db
    def _record(self, actor, outcome, now):
        key=hashlib.sha256(str(actor).encode()).hexdigest()
        with self._connect() as db:
            db.execute('INSERT INTO audit (at,actor_hash,event,outcome) VALUES (?,?,?,?)',(now,key,'collect',outcome))
        return outcome
    def check(self, *, actor, role, origin, expected_origin, csrf_cookie, csrf_header):
        now=self.clock()
        if not isinstance(actor,str) or not actor or role not in ('operator','admin'):
            return self._record(actor,'DENY_RBAC',now)
        try:
            actual=urlsplit(origin); expected=urlsplit(expected_origin)
            origin_ok=(actual.scheme,actual.netloc)==(expected.scheme,expected.netloc) and actual.scheme=='https' and not actual.username and not actual.password and not actual.path and not actual.query and not actual.fragment
        except (TypeError,ValueError):origin_ok=False
        if not origin_ok or not isinstance(csrf_cookie,str) or not 32<=len(csrf_cookie)<=256 or not isinstance(csrf_header,str) or not hmac.compare_digest(csrf_cookie,csrf_header):
            return self._record(actor,'DENY_CSRF',now)
        key=hashlib.sha256(actor.encode()).hexdigest()
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM rate WHERE at < ?', (now-self.interval,))
            count=db.execute('SELECT COUNT(*) FROM rate WHERE actor_hash=?',(key,)).fetchone()[0]
            outcome='DENY_RATE' if count>=self.max_requests else 'ALLOW'
            if outcome=='ALLOW':db.execute('INSERT INTO rate(actor_hash,at) VALUES (?,?)',(key,now))
            db.execute('INSERT INTO audit (at,actor_hash,event,outcome) VALUES (?,?,?,?)',(now,key,'collect',outcome))
        return outcome
