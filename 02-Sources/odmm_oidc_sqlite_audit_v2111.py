"""Transactional, hash-chained Operations authentication audit. Author: Abdelhalim Talbi.
Hashes detect accidental/tampered changes relative to a separately retained trusted head;
not a substitute for external signed anchoring.
"""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

OUTCOMES={'ALLOW','DENY'}
REASONS={'VERIFIED','IDENTITY_REJECTED','RESOLVER_FAILURE'}
GENESIS='0'*64

def digest(seq, timestamp, outcome, reason, previous):
    payload=json.dumps([seq,timestamp,outcome,reason,previous],separators=(',',':'),ensure_ascii=True)
    return hashlib.sha256(payload.encode('ascii')).hexdigest()

class SQLiteOperationsAudit:
    def __init__(self, path):
        self.path=Path(path)
        if str(path)==':memory:':
            raise ValueError('PERSISTENT_AUDIT_PATH_REQUIRED')
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self._lock=RLock()
        with self._connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS auth_events (
                seq INTEGER PRIMARY KEY, timestamp TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK(outcome IN ('ALLOW','DENY')),
                reason TEXT NOT NULL CHECK(reason IN ('VERIFIED','IDENTITY_REJECTED','RESOLVER_FAILURE')),
                previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)''')
    def _connect(self):
        db=sqlite3.connect(str(self.path),timeout=10)
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('PRAGMA synchronous=FULL')
        return db
    def record(self, *, outcome, reason):
        if outcome not in OUTCOMES or reason not in REASONS:
            raise ValueError('INVALID_AUDIT_EVENT')
        stamp=datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            previous=db.execute('SELECT seq,event_hash FROM auth_events ORDER BY seq DESC LIMIT 1').fetchone()
            seq=(previous[0]+1) if previous else 1
            prev_hash=previous[1] if previous else GENESIS
            hash_value=digest(seq,stamp,outcome,reason,prev_hash)
            db.execute('INSERT INTO auth_events VALUES (?,?,?,?,?,?)',
                       (seq,stamp,outcome,reason,prev_hash,hash_value))
        return {'schema':'odmm.operations.auth.audit.v2111','seq':seq,'timestamp':stamp,
                'outcome':outcome,'reason':reason,'previous_hash':prev_hash,'event_hash':hash_value}
    def snapshot(self,limit=1000):
        if type(limit) is not int or not 1<=limit<=10000:raise ValueError('INVALID_LIMIT')
        with self._connect() as db:
            rows=db.execute('SELECT seq,timestamp,outcome,reason,previous_hash,event_hash FROM auth_events ORDER BY seq DESC LIMIT ?', (limit,)).fetchall()
        return [dict(zip(('seq','timestamp','outcome','reason','previous_hash','event_hash'),row)) for row in reversed(rows)]
    def verify(self, trusted_head=None):
        with self._connect() as db:
            rows=db.execute('SELECT seq,timestamp,outcome,reason,previous_hash,event_hash FROM auth_events ORDER BY seq').fetchall()
        prev=GENESIS
        for expected,row in enumerate(rows,1):
            seq,stamp,outcome,reason,old,hash_value=row
            if seq!=expected or old!=prev or outcome not in OUTCOMES or reason not in REASONS or digest(seq,stamp,outcome,reason,old)!=hash_value:
                return {'valid':False,'events_checked':expected-1,'reason':'CHAIN_MISMATCH'}
            prev=hash_value
        if trusted_head is not None and trusted_head!=prev:
            return {'valid':False,'events_checked':len(rows),'reason':'TRUSTED_HEAD_MISMATCH'}
        return {'valid':True,'events_checked':len(rows),'head':prev}

def create_sqlite_audited_oidc_operations_app(*, audit_path, **kwargs):
    """Reuse the existing policy verifier and fail-closed route wrapper."""
    from odmm_oidc_audit_v2110 import create_audited_oidc_operations_app
    from odmm_oidc_audit_v2110 import OperationsAudit
    # Adapter conforms to the existing validated interface without changing upstream auth.
    class Adapter(OperationsAudit):
        def __init__(self,path):self.store=SQLiteOperationsAudit(path)
        def record(self,*,outcome,reason):return self.store.record(outcome=outcome,reason=reason)
        def snapshot(self):return self.store.snapshot()
    audit=Adapter(audit_path)
    return create_audited_oidc_operations_app(audit=audit,**kwargs)
