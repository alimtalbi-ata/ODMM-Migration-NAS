"""Lease fencing for already claimed supervised retries. No LDAP execution.

External workers MUST check the epoch at the effect boundary; SQLite cannot fence
an external worker by itself. Clock values must come from a trusted clock.
"""
from ldaps_recovery_dispatch import RecoveryDispatcher, DispatchError
from ldaps_supervised_recovery import _identifier
from directory_sync_journal import digest

class LeaseError(ValueError): pass

class RecoveryLease:
    def __init__(self, coordinator):
        self.dispatch=RecoveryDispatcher(coordinator)
        self.db=coordinator.db
        self.db.execute("""CREATE TABLE IF NOT EXISTS ldaps_recovery_leases (
            event_id TEXT PRIMARY KEY, owner TEXT NOT NULL, epoch INTEGER NOT NULL,
            expires_at INTEGER NOT NULL, record_hash TEXT NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS ldaps_recovery_lease_events (
            seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL, action TEXT NOT NULL,
            owner TEXT NOT NULL, epoch INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)""")

    def _verify(self):
        self.dispatch._verify()
        rows=self.db.execute('SELECT seq,event_id,action,owner,epoch,expires_at,previous_hash,event_hash FROM ldaps_recovery_lease_events ORDER BY seq').fetchall()
        previous='0'*64;states={}
        for expected,(seq,eid,action,owner,epoch,expiry,ph,h) in enumerate(rows,1):
            obj=dict(seq=seq,event_id=eid,action=action,owner=owner,epoch=epoch,expires_at=expiry,previous_hash=ph)
            if seq!=expected or ph!=previous or digest(obj)!=h:raise LeaseError('LEASE_JOURNAL_TAMPERED')
            previous=h;old=states.get(eid)
            if action=='START':
                if old or epoch!=1:raise LeaseError('LEASE_HISTORY_INVALID')
            elif action=='RENEW':
                if not old or (owner,epoch)!=(old[0],old[1]) or expiry<=old[2]:raise LeaseError('LEASE_HISTORY_INVALID')
            elif action=='TRANSFER':
                if not old or epoch!=old[1]+1 or owner==old[0] or expiry<=old[2]:raise LeaseError('LEASE_HISTORY_INVALID')
            else:raise LeaseError('LEASE_HISTORY_INVALID')
            states[eid]=(owner,epoch,expiry)
        saved=self.db.execute('SELECT event_id,owner,epoch,expires_at,record_hash FROM ldaps_recovery_leases').fetchall()
        if len(saved)!=len(states):raise LeaseError('LEASE_STATE_TAMPERED')
        for eid,owner,epoch,expiry,h in saved:
            if digest(dict(event_id=eid,owner=owner,epoch=epoch,expires_at=expiry))!=h or states.get(eid)!=(owner,epoch,expiry):raise LeaseError('LEASE_STATE_TAMPERED')
            dispatch=self.db.execute('SELECT state FROM ldaps_recovery_dispatch WHERE new_event_id=?',(eid,)).fetchone()
            if not dispatch:raise LeaseError('ORPHAN_LEASE')
        return states

    def verify(self):
        return dict(status='LOCAL_HASHES_VERIFIED_NOT_AUTHENTICATED',count=len(self._verify()),cutover_authorized=False)

    def _event(self,eid,action,owner,epoch,expiry):
        last=self.db.execute('SELECT seq,event_hash FROM ldaps_recovery_lease_events ORDER BY seq DESC LIMIT 1').fetchone()
        seq=last[0]+1 if last else 1
        obj=dict(seq=seq,event_id=eid,action=action,owner=owner,epoch=epoch,expires_at=expiry,previous_hash=last[1] if last else '0'*64)
        self.db.execute('INSERT INTO ldaps_recovery_lease_events VALUES (?,?,?,?,?,?,?,?)',(seq,eid,action,owner,epoch,expiry,obj['previous_hash'],digest(obj)))

    def transition(self, *, event_id, owner, epoch, now, ttl, action):
        _identifier(event_id);_identifier(owner)
        if type(epoch)!=int or epoch<1 or type(now)!=int or now<0 or type(ttl)!=int or not 1<=ttl<=86400 or action not in ('START','RENEW','TRANSFER'):
            raise LeaseError('INVALID_REQUEST')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            states=self._verify()
            if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ldaps_lease_finalizations'").fetchone() and self.db.execute('SELECT 1 FROM ldaps_lease_finalizations WHERE event_id=?',(event_id,)).fetchone():
                raise LeaseError('ALREADY_FINALIZED')
            dispatch=self.db.execute('SELECT state,owner,epoch,claimed_at FROM ldaps_recovery_dispatch WHERE new_event_id=?',(event_id,)).fetchone()
            if not dispatch or dispatch[0]!='CLAIMED':raise LeaseError('NOT_CLAIMED')
            old=states.get(event_id)
            if action=='START':
                if old or (owner,epoch)!=(dispatch[1],dispatch[2]) or now<dispatch[3]:raise LeaseError('INVALID_START')
            elif action=='RENEW':
                if not old or (owner,epoch)!=(old[0],old[1]) or now>=old[2]:raise LeaseError('STALE_LEASE')
            else:
                if not old or epoch!=old[1]+1 or owner==old[0] or now<old[2]:raise LeaseError('TRANSFER_NOT_ALLOWED')
            expiry=now+ttl
            if old and expiry<=old[2]:raise LeaseError('EXPIRY_NOT_EXTENDED')
            obj=dict(event_id=event_id,owner=owner,epoch=epoch,expires_at=expiry)
            self.db.execute('INSERT INTO ldaps_recovery_leases VALUES (?,?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET owner=excluded.owner,epoch=excluded.epoch,expires_at=excluded.expires_at,record_hash=excluded.record_hash',(event_id,owner,epoch,expiry,digest(obj)))
            self._event(event_id,action,owner,epoch,expiry)
            self.db.commit()
            return dict(status='LEASE_'+action,owner=owner,epoch=epoch,expires_at=expiry,automatic_retry=False,cutover_authorized=False)
        except BaseException:
            self.db.rollback();raise

    def check(self, *, event_id, owner, epoch, now):
        _identifier(event_id);_identifier(owner)
        if type(epoch)!=int or type(now)!=int or now<0:raise LeaseError('INVALID_REQUEST')
        states=self._verify();record=states.get(event_id)
        dispatch=self.db.execute('SELECT state FROM ldaps_recovery_dispatch WHERE new_event_id=?',(event_id,)).fetchone()
        return bool(record and dispatch and dispatch[0]=='CLAIMED' and (owner,epoch)==record[:2] and now<record[2])
