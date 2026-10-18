"""Fail-closed leased finalization with atomic, hash-chained evidence.

Finalizes a *local* execution record, not an LDAP action or cutover.
"""
from ldaps_recovery_lease import RecoveryLease, LeaseError
from ldaps_supervised_recovery import _identifier
from directory_sync_journal import digest

class FinalizationError(ValueError): pass

class LeasedFinalizer:
    def __init__(self, coordinator):
        self.lease=RecoveryLease(coordinator)
        self.db=coordinator.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS ldaps_lease_finalizations (
          event_id TEXT PRIMARY KEY, owner TEXT NOT NULL, epoch INTEGER NOT NULL,
          at INTEGER NOT NULL, outcome TEXT NOT NULL, record_hash TEXT NOT NULL)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS ldaps_lease_finalization_events (
          seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, owner TEXT NOT NULL,
          epoch INTEGER NOT NULL, at INTEGER NOT NULL, outcome TEXT NOT NULL,
          previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)''')

    def _verify_locked(self):
        states=self.lease._verify()
        previous='0'*64
        events=self.db.execute('SELECT seq,event_id,owner,epoch,at,outcome,previous_hash,event_hash FROM ldaps_lease_finalization_events ORDER BY seq').fetchall()
        seen={}
        for n,(seq,eid,owner,epoch,at,outcome,ph,h) in enumerate(events,1):
            obj=dict(seq=seq,event_id=eid,owner=owner,epoch=epoch,at=at,outcome=outcome,previous_hash=ph)
            if seq!=n or ph!=previous or digest(obj)!=h or eid in seen or outcome not in ('FINISHED','ABORTED'):
                raise FinalizationError('FINALIZATION_JOURNAL_TAMPERED')
            if eid not in states or (owner,epoch)!=states[eid][:2]:
                # A later lease transfer cannot be valid after finalization.
                raise FinalizationError('FINALIZATION_LEASE_MISMATCH')
            previous=h;seen[eid]=(owner,epoch,at,outcome)
        records=self.db.execute('SELECT event_id,owner,epoch,at,outcome,record_hash FROM ldaps_lease_finalizations').fetchall()
        if len(records)!=len(seen):raise FinalizationError('FINALIZATION_STATE_TAMPERED')
        for eid,owner,epoch,at,outcome,h in records:
            if digest(dict(event_id=eid,owner=owner,epoch=epoch,at=at,outcome=outcome))!=h or seen.get(eid)!=(owner,epoch,at,outcome):
                raise FinalizationError('FINALIZATION_STATE_TAMPERED')
        return states,seen

    def verify(self):
        _,done=self._verify_locked()
        return dict(status='LOCAL_HASHES_VERIFIED_NOT_AUTHENTICATED',count=len(done),cutover_authorized=False)

    def finish(self, *, event_id, owner, epoch, at, outcome):
        _identifier(event_id);_identifier(owner)
        if type(epoch)!=int or epoch<1 or type(at)!=int or at<0 or outcome not in ('FINISHED','ABORTED'):
            raise FinalizationError('INVALID_REQUEST')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            states,done=self._verify_locked()
            if event_id in done:raise FinalizationError('ALREADY_FINALIZED')
            lease=states.get(event_id)
            dispatch=self.db.execute('SELECT state,claimed_at FROM ldaps_recovery_dispatch WHERE new_event_id=?',(event_id,)).fetchone()
            if not lease or not dispatch or dispatch[0]!='CLAIMED' or at<dispatch[1] or at>=lease[2] or (owner,epoch)!=lease[:2]:
                raise FinalizationError('STALE_OWNER_OR_EXPIRED_LEASE')
            obj=dict(event_id=event_id,owner=owner,epoch=epoch,at=at,outcome=outcome)
            self.db.execute('INSERT INTO ldaps_lease_finalizations VALUES (?,?,?,?,?,?)',(event_id,owner,epoch,at,outcome,digest(obj)))
            last=self.db.execute('SELECT seq,event_hash FROM ldaps_lease_finalization_events ORDER BY seq DESC LIMIT 1').fetchone()
            seq=last[0]+1 if last else 1
            event=dict(seq=seq,**obj,previous_hash=last[1] if last else '0'*64)
            self.db.execute('INSERT INTO ldaps_lease_finalization_events VALUES (?,?,?,?,?,?,?,?)',(seq,event_id,owner,epoch,at,outcome,event['previous_hash'],digest(event)))
            self.db.commit()
            return dict(status=outcome,epoch=epoch,owner=owner,cutover_authorized=False,automatic_retry=False,external_effect_verified=False)
        except BaseException:
            self.db.rollback();raise
