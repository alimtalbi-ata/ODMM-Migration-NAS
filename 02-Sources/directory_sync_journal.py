"""Transactional LDAPS sync attempt journal; offline evidence, never cutover authority."""
import hashlib
import json
import re
import sqlite3
from directory_sync_health import assess_directory_sync_health

STATUSES={'SUCCESS','NETWORK_FAILURE','TLS_FAILURE','PAGINATION_FAILURE','IMPORT_FAILURE'}
class SyncJournalError(ValueError): pass

def digest(v):
    return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

class DirectorySyncJournal:
    def __init__(self, db):
        self.db=db
        self.db.execute('''CREATE TABLE IF NOT EXISTS directory_sync_events (
            seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, at INTEGER NOT NULL UNIQUE,
            status TEXT NOT NULL, digest TEXT, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)''')

    def append(self, event_id, at, status, snapshot_digest=None, *, _within_transaction=False):
        if not isinstance(event_id,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',event_id):
            raise SyncJournalError('INVALID_EVENT_ID')
        if type(at) is not int or at < 0 or status not in STATUSES:
            raise SyncJournalError('INVALID_OBSERVATION')
        if (status=='SUCCESS' and (not isinstance(snapshot_digest,str) or not re.fullmatch('[0-9a-f]{64}',snapshot_digest))) or (status!='SUCCESS' and snapshot_digest is not None):
            raise SyncJournalError('INVALID_DIGEST')
        try:
            if not _within_transaction: self.db.execute('BEGIN IMMEDIATE')
            self._verify_locked()
            last=self.db.execute('SELECT seq,at,event_hash FROM directory_sync_events ORDER BY seq DESC LIMIT 1').fetchone()
            if last and at<=last[1]:raise SyncJournalError('NON_MONOTONIC_TIME')
            seq=(last[0]+1) if last else 1
            prev=last[2] if last else '0'*64
            event={'seq':seq,'event_id':event_id,'at':at,'status':status,'digest':snapshot_digest,'previous_hash':prev}
            h=digest(event)
            self.db.execute('INSERT INTO directory_sync_events VALUES (?,?,?,?,?,?,?)',(seq,event_id,at,status,snapshot_digest,prev,h))
            if not _within_transaction: self.db.commit()
            return {'seq':seq,'event_hash':h,'cutover_authorized':False}
        except Exception as e:
            if not _within_transaction: self.db.rollback()
            if isinstance(e,sqlite3.IntegrityError):raise SyncJournalError('DUPLICATE_EVENT') from e
            raise

    def _verify_locked(self):
        rows=self.db.execute('SELECT seq,event_id,at,status,digest,previous_hash,event_hash FROM directory_sync_events ORDER BY seq').fetchall()
        prev='0'*64;at=-1
        for i,(seq,event_id,t,status,d,ph,h) in enumerate(rows,1):
            event={'seq':seq,'event_id':event_id,'at':t,'status':status,'digest':d,'previous_hash':ph}
            if seq!=i or t<=at or ph!=prev or digest(event)!=h:
                raise SyncJournalError('JOURNAL_TAMPERED')
            prev=h;at=t
        return rows

    def verify(self):
        rows=self._verify_locked()
        return {'status':'CHAIN_INTACT_UNAUTHENTICATED','count':len(rows),'head_hash':rows[-1][6] if rows else '0'*64,'cutover_authorized':False}

    def observations(self):
        rows=self._verify_locked()
        if not rows:raise SyncJournalError('NO_OBSERVATIONS')
        return [{'at':r[2],'status':r[3],'digest':r[4]} for r in rows]

    def assess_health(self, ledger, *, now, max_age_seconds):
        return assess_directory_sync_health(ledger,now=now,max_age_seconds=max_age_seconds,observations=self.observations())
