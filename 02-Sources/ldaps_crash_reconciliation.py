"""Durable, read-only evidence reconciliation for simulated LDAPS effects.

No automatic retries, no real target actions and no production cutover.
"""
import sqlite3
from directory_sync_journal import digest
from ldaps_supervised_recovery import _identifier
from ldaps_durable_target import DurableEffectReconciler

class CrashReconciliationError(ValueError): pass

class CrashReconciliationLedger:
    def __init__(self, coordinator, target):
        self.db=coordinator.db
        self.target=target
        self.reconciler=DurableEffectReconciler(coordinator,target)
        self.db.execute('''CREATE TABLE IF NOT EXISTS ldaps_crash_reconciliations (
            seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL, request_id TEXT NOT NULL,
            observed_at INTEGER NOT NULL, state TEXT NOT NULL, target_hash TEXT,
            local_hash TEXT, previous_hash TEXT NOT NULL, evidence_hash TEXT NOT NULL,
            UNIQUE(event_id,request_id,observed_at))''')

    def _rows(self):
        return self.db.execute('SELECT seq,event_id,request_id,observed_at,state,target_hash,local_hash,previous_hash,evidence_hash FROM ldaps_crash_reconciliations ORDER BY seq').fetchall()

    def verify(self):
        previous='GENESIS'
        rows=self._rows()
        for seq,event_id,request_id,at,state,remote,local,prev,h in rows:
            obj=dict(seq=seq,event_id=event_id,request_id=request_id,observed_at=at,state=state,target_hash=remote,local_hash=local,previous_hash=previous)
            if prev!=previous or digest(obj)!=h:raise CrashReconciliationError('RECONCILIATION_AUDIT_TAMPERED')
            previous=h
        return dict(status='RECONCILIATION_AUDIT_VERIFIED',count=len(rows),last_hash=previous)

    def inspect(self,event_id,request_id):
        _identifier(event_id);_identifier(request_id)
        self.verify()
        remote=self.target.lookup(event_id,request_id)
        exists=self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ldaps_simulated_effect_receipts'").fetchone()
        local=(self.db.execute('SELECT target_hash FROM ldaps_simulated_effect_receipts WHERE event_id=? AND request_id=?',(event_id,request_id)).fetchone() if exists else None)
        if remote is None and local is None:state='NOT_APPLIED'
        elif remote is not None and local is None:state='TARGET_COMMITTED_RECEIPT_MISSING'
        elif remote is None:state='RECEIPT_WITHOUT_TARGET'
        elif remote['evidence_sha256']!=local[0]:state='EVIDENCE_MISMATCH'
        else:state='CONSISTENT'
        return dict(event_id=event_id,request_id=request_id,state=state,target_hash=remote['evidence_sha256'] if remote else None,local_hash=local[0] if local else None,manual_review_required=state!='CONSISTENT',automatic_retry=False,cutover_authorized=False)

    def record(self,event_id,request_id,*,observed_at):
        if type(observed_at)!=int or observed_at<0:raise CrashReconciliationError('INVALID_TIMESTAMP')
        # Snapshot is inspected again while the coordinator's SQLite write lock is held.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.verify()
            observation=self.inspect(event_id,request_id)
            last=self.db.execute('SELECT seq,evidence_hash FROM ldaps_crash_reconciliations ORDER BY seq DESC LIMIT 1').fetchone()
            seq=last[0]+1 if last else 1
            prev=last[1] if last else 'GENESIS'
            obj=dict(seq=seq,event_id=event_id,request_id=request_id,observed_at=observed_at,state=observation['state'],target_hash=observation['target_hash'],local_hash=observation['local_hash'],previous_hash=prev)
            h=digest(obj)
            self.db.execute('INSERT INTO ldaps_crash_reconciliations VALUES (?,?,?,?,?,?,?,?,?)',(seq,event_id,request_id,observed_at,observation['state'],observation['target_hash'],observation['local_hash'],prev,h))
            self.db.execute('COMMIT')
            return dict(**observation,evidence_sha256=h,status='RECONCILIATION_RECORDED')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
