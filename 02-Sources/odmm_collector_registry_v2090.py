"""Transactional replay registry and key lifecycle. Author: Abdelhalim Talbi.

SQLite is local to one trust domain; shared network filesystems are not supported.
"""
import hashlib
import hmac
import json
import sqlite3
import os
from datetime import datetime, timezone
from pathlib import Path
from odmm_netapp_collector_v2089 import verify_envelope, CollectorError

class CollectorRegistry:
    def __init__(self, path):
        self.path=str(path)
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        if not Path(path).exists():
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            os.close(fd)
        with self._connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS keys(collector TEXT NOT NULL,kid TEXT NOT NULL,secret BLOB NOT NULL,status TEXT NOT NULL CHECK(status IN ('active','revoked')),PRIMARY KEY(collector,kid));
            CREATE TABLE IF NOT EXISTS nonces(collector TEXT NOT NULL,kid TEXT NOT NULL,nonce TEXT NOT NULL,seen_at TEXT NOT NULL,PRIMARY KEY(collector,kid,nonce));
            CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, details TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);''')
    def _connect(self):
        db=sqlite3.connect(self.path,timeout=20,isolation_level=None)
        db.execute('PRAGMA busy_timeout=20000')
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        return db
    @staticmethod
    def _audit(db,event,details):
        row=db.execute('SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
        prev=row[0] if row else '0'*64
        data=json.dumps({'event':event,'details':details,'previous_hash':prev},sort_keys=True,separators=(',',':'))
        digest=hashlib.sha256(data.encode()).hexdigest()
        db.execute('INSERT INTO audit(event,details,previous_hash,entry_hash) VALUES(?,?,?,?)',(event,json.dumps(details,sort_keys=True),prev,digest))
    def register_key(self,collector,kid,secret):
        if not isinstance(secret,bytes) or len(secret)<32:raise CollectorError('WEAK_KEY')
        if not all(isinstance(v,str) and 0<len(v)<=128 and all(c.isalnum() and c.isascii() or c in '_.-' for c in v) for v in (collector,kid)):raise CollectorError('IDENTIFIER_INVALID')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM keys WHERE collector=? AND kid=?',(collector,kid)).fetchone():
                raise CollectorError('KEY_ID_ALREADY_USED')
            db.execute('INSERT INTO keys VALUES(?,?,?,?)',(collector,kid,secret,'active'))
            self._audit(db,'KEY_REGISTERED',{'collector':collector,'kid':kid})
            db.commit()
    def revoke_key(self,collector,kid):
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            cur=db.execute("UPDATE keys SET status='revoked' WHERE collector=? AND kid=? AND status='active'",(collector,kid))
            if cur.rowcount!=1:raise CollectorError('KEY_NOT_ACTIVE')
            self._audit(db,'KEY_REVOKED',{'collector':collector,'kid':kid})
            db.commit()
    def verify_once(self,envelope,*,now=None,max_age_seconds=300):
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute("SELECT secret FROM keys WHERE collector=? AND kid=? AND status='active'",(envelope.get('collector_id'),envelope.get('key_id'))).fetchone() if isinstance(envelope,dict) else None
            if not row:raise CollectorError('UNKNOWN_OR_REVOKED_KEY')
            # Transaction holds the write lock until nonce insertion is committed.
            payload=verify_envelope(envelope,keyring={(envelope['collector_id'],envelope['key_id']):row[0]},used_nonces=set(),now=now,max_age_seconds=max_age_seconds)
            try:
                db.execute('INSERT INTO nonces VALUES(?,?,?,?)',(envelope['collector_id'],envelope['key_id'],envelope['nonce'],(now or datetime.now(timezone.utc)).isoformat()))
            except sqlite3.IntegrityError:raise CollectorError('REPLAY_DETECTED')
            self._audit(db,'ENVELOPE_ACCEPTED',{'collector':envelope['collector_id'],'kid':envelope['key_id'],'nonce':envelope['nonce']})
            db.commit()
            return payload
    def export_audit(self):
        with self._connect() as db:
            rows=db.execute('SELECT seq,event,details,previous_hash,entry_hash FROM audit ORDER BY seq').fetchall()
        return [{'seq':r[0],'event':r[1],'details':json.loads(r[2]),'previous_hash':r[3],'entry_hash':r[4]} for r in rows]
    @staticmethod
    def verify_audit(rows):
        prev='0'*64
        for n,row in enumerate(rows,1):
            if row['seq']!=n or row['previous_hash']!=prev:return False
            data=json.dumps({'event':row['event'],'details':row['details'],'previous_hash':prev},sort_keys=True,separators=(',',':'))
            prev=hashlib.sha256(data.encode()).hexdigest()
            if not hmac.compare_digest(prev,row['entry_hash']):return False
        return True
