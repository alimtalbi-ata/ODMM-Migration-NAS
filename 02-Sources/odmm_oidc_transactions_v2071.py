"""Shared, atomic, single-use OIDC PKCE transactions. Auteur: Abdelhalim Talbi."""
import hashlib, hmac, secrets, sqlite3, time
from pathlib import Path
from urllib.parse import urlencode
from odmm_oidc_pkce_v2068 import _b64, _https_url, OIDCVerificationError

class SQLitePKCETransactions:
    """Shared SQLite backend for multi-worker login, not a substitute for callback browser binding."""
    def __init__(self, db_path, *, key, clock=None, ttl=300):
        if not isinstance(key,bytes) or len(key)<32 or not 30<=ttl<=600:
            raise ValueError('INVALID_PKCE_CONFIGURATION')
        self.db_path=str(db_path); self.key=key; self.clock=clock or time.time; self.ttl=ttl
        Path(self.db_path).parent.mkdir(parents=True,exist_ok=True)
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS oidc_pkce (state_hash TEXT PRIMARY KEY, nonce TEXT NOT NULL, verifier TEXT NOT NULL, redirect_uri TEXT NOT NULL, browser_hash TEXT NOT NULL, expires REAL NOT NULL)')
    def _db(self):
        from contextlib import contextmanager
        @contextmanager
        def connect():
            db=sqlite3.connect(self.db_path,timeout=10,isolation_level=None)
            try:
                db.execute('PRAGMA busy_timeout=10000')
                yield db
            finally:db.close()
        return connect()
    def _digest(self, value):
        if not isinstance(value,str) or not 16<=len(value)<=4096:
            raise OIDCVerificationError('INVALID_BINDING')
        return hmac.new(self.key,value.encode(),hashlib.sha256).hexdigest()
    def begin(self, *, authorize_endpoint, client_id, redirect_uri, browser_binding, scope='openid profile email'):
        _https_url(authorize_endpoint);_https_url(redirect_uri)
        if not isinstance(client_id,str) or not 1<=len(client_id)<=256:raise OIDCVerificationError('INVALID_CLIENT')
        binding=self._digest(browser_binding)
        state=secrets.token_urlsafe(32);nonce=secrets.token_urlsafe(32);verifier=secrets.token_urlsafe(48)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM oidc_pkce WHERE expires<=?',(self.clock(),))
            db.execute('INSERT INTO oidc_pkce VALUES(?,?,?,?,?,?)',(self._digest(state),nonce,verifier,redirect_uri,binding,self.clock()+self.ttl))
            db.execute('COMMIT')
        challenge=_b64(hashlib.sha256(verifier.encode()).digest())
        url=authorize_endpoint+'?'+urlencode({'response_type':'code','client_id':client_id,'redirect_uri':redirect_uri,'scope':scope,'state':state,'nonce':nonce,'code_challenge':challenge,'code_challenge_method':'S256'})
        return {'url':url,'state':state}
    def consume(self, *, state, code, browser_binding):
        if not isinstance(code,str) or not 1<=len(code)<=4096:raise OIDCVerificationError('INVALID_CALLBACK')
        state_hash=self._digest(state); binding=self._digest(browser_binding)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT nonce,verifier,redirect_uri,browser_hash,expires FROM oidc_pkce WHERE state_hash=?',(state_hash,)).fetchone()
            if row is None or row[4]<=self.clock() or not hmac.compare_digest(row[3],binding):
                db.execute('ROLLBACK')
                raise OIDCVerificationError('STATE_UNKNOWN_EXPIRED_OR_BINDING_MISMATCH')
            db.execute('DELETE FROM oidc_pkce WHERE state_hash=?',(state_hash,))
            db.execute('COMMIT')
        return {'code':code,'nonce':row[0],'code_verifier':row[1],'redirect_uri':row[2]}
