"""Fail-closed, auditable pre-effect permits for supervised LDAPS workers.

Permits are not external fencing: the target must enforce epoch atomically at effect time.
No LDAP requests or automatic retry are performed here.
"""
from ldaps_lease_finalization import LeasedFinalizer
from ldaps_supervised_recovery import _identifier
from directory_sync_journal import digest

class EffectFenceError(ValueError): pass

class EffectFence:
    def __init__(self, coordinator):
        self.finalizer=LeasedFinalizer(coordinator)
        self.db=coordinator.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS ldaps_effect_permits (
            seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL, owner TEXT NOT NULL,
            epoch INTEGER NOT NULL, at INTEGER NOT NULL, operation TEXT NOT NULL,
            previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)''')

    def _verify_locked(self):
        states,done=self.finalizer._verify_locked()
        previous='0'*64
        rows=self.db.execute('SELECT seq,event_id,owner,epoch,at,operation,previous_hash,event_hash FROM ldaps_effect_permits ORDER BY seq').fetchall()
        for n,(seq,eid,owner,epoch,at,operation,ph,h) in enumerate(rows,1):
            obj=dict(seq=seq,event_id=eid,owner=owner,epoch=epoch,at=at,operation=operation,previous_hash=ph)
            if seq!=n or ph!=previous or digest(obj)!=h:
                raise EffectFenceError('EFFECT_AUDIT_TAMPERED')
            previous=h
        return states,done,len(rows)

    def authorize(self, *, event_id, owner, epoch, now, operation):
        _identifier(event_id);_identifier(owner);_identifier(operation)
        if type(epoch)!=int or epoch<1 or type(now)!=int or now<0:
            raise EffectFenceError('INVALID_REQUEST')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            states,done,count=self._verify_locked()
            lease=states.get(event_id)
            dispatch=self.db.execute('SELECT state,claimed_at FROM ldaps_recovery_dispatch WHERE new_event_id=?',(event_id,)).fetchone()
            if event_id in done or not lease or not dispatch or dispatch[0]!='CLAIMED' or now<dispatch[1] or now>=lease[2] or (owner,epoch)!=lease[:2]:
                raise EffectFenceError('STALE_OR_UNAUTHORIZED_EFFECT')
            last=self.db.execute('SELECT event_hash FROM ldaps_effect_permits ORDER BY seq DESC LIMIT 1').fetchone()
            obj=dict(seq=count+1,event_id=event_id,owner=owner,epoch=epoch,at=now,operation=operation,previous_hash=last[0] if last else '0'*64)
            h=digest(obj)
            self.db.execute('INSERT INTO ldaps_effect_permits VALUES (?,?,?,?,?,?,?,?)',(count+1,event_id,owner,epoch,now,operation,obj['previous_hash'],h))
            self.db.commit()
            return dict(status='LOCAL_PRE_EFFECT_PERMIT',event_id=event_id,owner=owner,epoch=epoch,operation=operation,evidence_sha256=h,external_effect_executed=False,external_fencing_enforced=False,cutover_authorized=False)
        except BaseException:
            self.db.rollback();raise

    def verify(self):
        _,_,count=self._verify_locked()
        return dict(status='LOCAL_HASHES_VERIFIED_NOT_AUTHENTICATED',count=count,external_fencing_enforced=False,cutover_authorized=False)
