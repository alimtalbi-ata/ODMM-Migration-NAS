"""Simulation-only fenced effect adapter. No real LDAP/NAS calls or cutover.

The simulated target enforces epochs under its own lock at effect time. A real
adapter MUST provide equivalent target-side atomic enforcement, not a callback.
"""
import threading
from directory_sync_journal import digest
from ldaps_effect_fence import EffectFence
from ldaps_supervised_recovery import _identifier

class FencedExecutionError(ValueError): pass

class SimulatedFencedTarget:
    def __init__(self):
        self.lock=threading.RLock()
        self.epochs={}
        self.effects={}

    def advance_epoch(self, event_id, epoch):
        _identifier(event_id)
        if type(epoch)!=int or epoch<1:raise FencedExecutionError('INVALID_EPOCH')
        with self.lock:
            previous=self.epochs.get(event_id,0)
            if epoch<previous:raise FencedExecutionError('STALE_EPOCH')
            self.epochs[event_id]=epoch

    def apply(self, *, event_id, owner, epoch, operation, permit_hash, request_id):
        for v in (event_id,owner,operation,request_id):_identifier(v)
        with self.lock:
            if self.epochs.get(event_id)!=epoch:raise FencedExecutionError('TARGET_FENCING_REJECTED')
            key=(event_id,request_id)
            if key in self.effects:raise FencedExecutionError('DUPLICATE_EFFECT_REJECTED')
            result=dict(event_id=event_id,owner=owner,epoch=epoch,operation=operation,request_id=request_id,permit_hash=permit_hash)
            self.effects[key]=digest(result)
            return dict(status='SIMULATED_EFFECT_APPLIED',evidence_sha256=self.effects[key],external_effect_executed=False,cutover_authorized=False)

class FencedExecutionAdapter:
    """Only accepts SimulatedFencedTarget; does not claim real remote fencing."""
    def __init__(self, coordinator, target):
        if type(target) is not SimulatedFencedTarget:raise FencedExecutionError('SIMULATED_TARGET_ONLY')
        self.fence=EffectFence(coordinator)
        self.target=target
        self.db=coordinator.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS ldaps_simulated_effect_receipts (
            request_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,owner TEXT NOT NULL,
            epoch INTEGER NOT NULL,at INTEGER NOT NULL,permit_hash TEXT NOT NULL,
            target_hash TEXT NOT NULL,receipt_hash TEXT NOT NULL)''')

    def execute(self, *, event_id, owner, epoch, now, operation, request_id):
        _identifier(request_id)
        if self.db.execute('SELECT 1 FROM ldaps_simulated_effect_receipts WHERE request_id=?',(request_id,)).fetchone():
            raise FencedExecutionError('DUPLICATE_REQUEST')
        permit=self.fence.authorize(event_id=event_id,owner=owner,epoch=epoch,now=now,operation=operation)
        # The simulated target independently checks epoch under its own lock.
        outcome=self.target.apply(event_id=event_id,owner=owner,epoch=epoch,operation=operation,
                                  permit_hash=permit['evidence_sha256'],request_id=request_id)
        receipt=dict(request_id=request_id,event_id=event_id,owner=owner,epoch=epoch,at=now,
                     permit_hash=permit['evidence_sha256'],target_hash=outcome['evidence_sha256'])
        try:
            self.db.execute('INSERT INTO ldaps_simulated_effect_receipts VALUES (?,?,?,?,?,?,?,?)',
                            (*receipt.values(),digest(receipt)))
        except BaseException as exc:
            # The simulated effect may already exist: fail closed, never retry silently.
            raise FencedExecutionError('EFFECT_RECEIPT_FAILED_MANUAL_RECONCILIATION_REQUIRED') from exc
        return dict(status='SIMULATED_FENCED_EFFECT_RECORDED',receipt_sha256=digest(receipt),
                    external_effect_executed=False,external_fencing_enforced=False,
                    automatic_retry=False,cutover_authorized=False)

    def verify(self):
        self.fence.verify()
        rows=self.db.execute('SELECT request_id,event_id,owner,epoch,at,permit_hash,target_hash,receipt_hash FROM ldaps_simulated_effect_receipts').fetchall()
        for request_id,event_id,owner,epoch,at,permit_hash,target_hash,h in rows:
            obj=dict(request_id=request_id,event_id=event_id,owner=owner,epoch=epoch,at=at,permit_hash=permit_hash,target_hash=target_hash)
            if digest(obj)!=h:raise FencedExecutionError('RECEIPT_TAMPERED')
        return dict(status='SIMULATED_RECEIPTS_VERIFIED',count=len(rows),external_fencing_enforced=False)
