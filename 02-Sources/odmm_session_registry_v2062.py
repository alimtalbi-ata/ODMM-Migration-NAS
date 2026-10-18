"""Transactional server-side session lifecycle registry. Auteur: Abdelhalim Talbi.

Only opaque session identifiers are stored as keyed SHA256 digests; no raw token
is retained. SQLite transactional revocation and expiration. Not an OIDC provider.
"""
import hashlib
import hmac
import secrets
import sqlite3
import time
from contextlib import contextmanager

class SessionRegistry:
    def __init__(self, db_path, *, key, clock=None):
        if not isinstance(key,bytes) or len(key)<32: raise ValueError('SESSION_KEY_REQUIRED')
        self.db_path=str(db_path); self.key=key; self.clock=clock or time.time
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS sessions (digest TEXT PRIMARY KEY, actor TEXT NOT NULL, role TEXT NOT NULL, expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires)')
    @contextmanager
    def _db(self):
        db=sqlite3.connect(self.db_path,timeout=15)
        try:
            db.execute('PRAGMA busy_timeout=15000')
            with db:
                yield db
        finally:
            db.close()
    def _digest(self,token):
        if not isinstance(token,str) or len(token)<32: return None
        return hmac.new(self.key,token.encode(),hashlib.sha256).hexdigest()
    def issue(self, actor, role, *, ttl=900):
        if not isinstance(actor,str) or not actor or role not in ('viewer','operator','admin') or not 1<=ttl<=86400:
            raise ValueError('INVALID_SESSION')
        token=secrets.token_urlsafe(48); digest=self._digest(token)
        with self._db() as db:
            db.execute('INSERT INTO sessions(digest,actor,role,expires) VALUES(?,?,?,?)',(digest,actor,role,self.clock()+ttl))
        return token
    def resolve(self,token):
        digest=self._digest(token)
        if digest is None:return None
        with self._db() as db:
            row=db.execute('SELECT actor,role,expires,revoked FROM sessions WHERE digest=?',(digest,)).fetchone()
        if row is None or row[3] or row[2]<=self.clock():return None
        return {'actor':row[0],'role':row[1]}
    def revoke(self,token):
        digest=self._digest(token)
        if digest is None:return False
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            cursor=db.execute('UPDATE sessions SET revoked=1 WHERE digest=? AND revoked=0',(digest,))
            return cursor.rowcount==1
    def cleanup(self):
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            return db.execute('DELETE FROM sessions WHERE expires<=?',(self.clock(),)).rowcount
