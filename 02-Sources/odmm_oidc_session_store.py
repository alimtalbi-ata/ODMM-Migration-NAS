"""SQLite-backed, multi-worker OIDC state/session store (single shared filesystem)."""
import json
import os
import sqlite3
import time
from pathlib import Path
from odmm_operations_security import Principal

class SQLiteOIDCStore:
    def __init__(self, path, clock=None):
        self.path=Path(path).absolute()
        if self.path.is_symlink(): raise ValueError('SESSION_DB_SYMLINK_REJECTED')
        self.clock=clock or time.time
        self.path.parent.mkdir(parents=True,exist_ok=True)
        db=self._connect()
        try:
            db.execute('CREATE TABLE IF NOT EXISTS oidc_pending (state TEXT PRIMARY KEY, nonce TEXT NOT NULL, pkce TEXT NOT NULL, expires REAL NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS oidc_sessions (sid_hash TEXT PRIMARY KEY, subject TEXT NOT NULL, roles TEXT NOT NULL, expires REAL NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS oidc_csrf (sid_hash TEXT PRIMARY KEY, token_hash TEXT NOT NULL, FOREIGN KEY(sid_hash) REFERENCES oidc_sessions(sid_hash))')
        finally: db.close()
        if os.name=='posix': os.chmod(self.path,0o600)
    def _connect(self):
        db=sqlite3.connect(str(self.path),timeout=10,isolation_level=None)
        try:
            db.execute('PRAGMA busy_timeout=10000')
            return db
        except BaseException:
            db.close()
            raise
    def put_pending(self,state,nonce,pkce,expires):
        db=self._connect()
        try: db.execute('INSERT INTO oidc_pending VALUES (?,?,?,?)',(state,nonce,pkce,expires))
        finally: db.close()
    def consume_pending(self,state):
        db=self._connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT nonce,pkce,expires FROM oidc_pending WHERE state=?',(state,)).fetchone()
            db.execute('DELETE FROM oidc_pending WHERE state=?',(state,))
            db.execute('COMMIT')
            if row and row[2]>self.clock(): return row
            return None
        except BaseException:
            db.execute('ROLLBACK'); raise
        finally: db.close()
    def put_session(self,sid_hash,principal,expires):
        if not isinstance(principal,Principal) or not principal.verified: raise PermissionError('VERIFIED_PRINCIPAL_REQUIRED')
        db=self._connect()
        try: db.execute('INSERT INTO oidc_sessions VALUES (?,?,?,?)',(sid_hash,principal.subject,json.dumps(sorted(principal.roles)),expires))
        finally: db.close()
    def get_session(self,sid_hash):
        db=self._connect()
        try: row=db.execute('SELECT subject,roles,expires FROM oidc_sessions WHERE sid_hash=? AND expires>?',(sid_hash,self.clock())).fetchone()
        finally: db.close()
        if not row: return None
        return Principal(row[0],frozenset(json.loads(row[1])),verified=True)
    def bind_csrf(self,sid_hash,token):
        import hashlib
        digest=hashlib.sha256(token.encode()).hexdigest()
        db=self._connect()
        try: db.execute('INSERT OR REPLACE INTO oidc_csrf VALUES (?,?)',(sid_hash,digest))
        finally: db.close()
    def verify_csrf(self,sid_hash,token):
        """Atomic session+CSRF snapshot; rejects expired or removed sessions."""
        import hashlib,hmac
        if not isinstance(token,str) or not token or len(token)>512: return False
        digest=hashlib.sha256(token.encode('utf-8')).hexdigest()
        db=self._connect()
        try:
            row=db.execute('''SELECT c.token_hash FROM oidc_csrf c
                JOIN oidc_sessions s ON s.sid_hash=c.sid_hash
                WHERE c.sid_hash=? AND s.expires>?''',(sid_hash,self.clock())).fetchone()
            return bool(row and hmac.compare_digest(row[0],digest))
        finally: db.close()
    def delete_session(self,sid_hash):
        db=self._connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM oidc_csrf WHERE sid_hash=?',(sid_hash,))
            db.execute('DELETE FROM oidc_sessions WHERE sid_hash=?',(sid_hash,))
            db.execute('COMMIT')
        except BaseException:
            db.execute('ROLLBACK'); raise
        finally: db.close()
    def cleanup(self):
        db=self._connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            a=db.execute('DELETE FROM oidc_pending WHERE expires<=?',(self.clock(),)).rowcount
            b=db.execute('DELETE FROM oidc_sessions WHERE expires<=?',(self.clock(),)).rowcount
            db.execute('DELETE FROM oidc_csrf WHERE sid_hash NOT IN (SELECT sid_hash FROM oidc_sessions)')
            db.execute('COMMIT')
            return a,b
        except BaseException:
            db.execute('ROLLBACK'); raise
        finally: db.close()
