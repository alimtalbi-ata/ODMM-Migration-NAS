"""Durable simulation of target-side fencing, not an actual LDAP/NAS adapter.

Target and coordinator use separate SQLite databases. An effect is committed
at the simulated target before the coordinator can persist its receipt.
"""
import sqlite3
from directory_sync_journal import digest
from ldaps_supervised_recovery import _identifier

class DurableTargetError(ValueError): pass

class DurableFencedTarget:
    def __init__(self, db):
        self.db=db
        self.db.execute('''CREATE TABLE IF NOT EXISTS durable_target_epochs
                           (event_id TEXT PRIMARY KEY, epoch INTEGER NOT NULL)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS durable_target_effects
            (event_id TEXT NOT NULL, request_id TEXT NOT NULL, owner TEXT NOT NULL,
             epoch INTEGER NOT NULL, operation TEXT NOT NULL, permit_hash TEXT NOT NULL,
             evidence_hash TEXT NOT NULL, PRIMARY KEY(event_id,request_id))''')

    def advance_epoch(self,event_id,epoch):
        _identifier(event_id)
        if type(epoch)!=int or epoch<1:raise DurableTargetError('INVALID_EPOCH')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT epoch FROM durable_target_epochs WHERE event_id=?',(event_id,)).fetchone()
            if row and epoch<row[0]:raise DurableTargetError('STALE_EPOCH')
            self.db.execute('INSERT INTO durable_target_epochs VALUES (?,?) ON CONFLICT(event_id) DO UPDATE SET epoch=excluded.epoch',(event_id,epoch))
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise

    def lookup(self,event_id,request_id):
        _identifier(event_id);_identifier(request_id)
        row=self.db.execute('SELECT owner,epoch,operation,permit_hash,evidence_hash FROM durable_target_effects WHERE event_id=? AND request_id=?',(event_id,request_id)).fetchone()
        if row is None:return None
        owner,epoch,operation,permit_hash,evidence_hash=row
        obj=dict(event_id=event_id,owner=owner,epoch=epoch,operation=operation,request_id=request_id,permit_hash=permit_hash)
        if digest(obj)!=evidence_hash:raise DurableTargetError('TARGET_EVIDENCE_TAMPERED')
        return dict(**obj,evidence_sha256=evidence_hash)

    def apply(self,*,event_id,owner,epoch,operation,permit_hash,request_id):
        for v in (event_id,owner,operation,request_id,permit_hash):_identifier(v)
        if type(epoch)!=int or epoch<1:raise DurableTargetError('INVALID_EPOCH')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            current=self.db.execute('SELECT epoch FROM durable_target_epochs WHERE event_id=?',(event_id,)).fetchone()
            if current is None or current[0]!=epoch:raise DurableTargetError('TARGET_FENCING_REJECTED')
            obj=dict(event_id=event_id,owner=owner,epoch=epoch,operation=operation,request_id=request_id,permit_hash=permit_hash)
            h=digest(obj)
            existing=self.lookup(event_id,request_id)
            if existing is not None:
                if existing['evidence_sha256']!=h:raise DurableTargetError('IDEMPOTENCY_CONFLICT')
                status='ALREADY_APPLIED'
            else:
                self.db.execute('INSERT INTO durable_target_effects VALUES (?,?,?,?,?,?,?)',(event_id,request_id,owner,epoch,operation,permit_hash,h))
                status='SIMULATED_EFFECT_APPLIED'
            self.db.execute('COMMIT')
            return dict(status=status,evidence_sha256=h,external_effect_executed=False,cutover_authorized=False)
        except BaseException:
            self.db.execute('ROLLBACK');raise

    def verify(self):
        rows=self.db.execute('SELECT event_id,request_id FROM durable_target_effects').fetchall()
        for event_id,request_id in rows:self.lookup(event_id,request_id)
        return dict(status='DURABLE_SIMULATED_TARGET_VERIFIED',count=len(rows))

class DurableEffectReconciler:
    """Read-only cross-database comparison; never retries or fabricates receipts."""
    def __init__(self,coordinator,target):
        self.db=coordinator.db;self.target=target
    def inspect(self,event_id,request_id):
        remote=self.target.lookup(event_id,request_id)
        exists=self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ldaps_simulated_effect_receipts'").fetchone()
        local=(self.db.execute('SELECT target_hash FROM ldaps_simulated_effect_receipts WHERE event_id=? AND request_id=?',(event_id,request_id)).fetchone() if exists else None)
        if remote is None and local is None:state='NOT_APPLIED'
        elif remote is not None and local is None:state='TARGET_COMMITTED_RECEIPT_MISSING'
        elif remote is None:state='RECEIPT_WITHOUT_TARGET'
        elif remote['evidence_sha256']!=local[0]:state='EVIDENCE_MISMATCH'
        else:state='CONSISTENT'
        return dict(state=state,manual_review_required=state!='CONSISTENT',automatic_retry=False,cutover_authorized=False)
