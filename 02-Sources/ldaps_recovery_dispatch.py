"""Single-use, fenced dispatch of supervised LDAPS recovery reservations.

Only claims a retry for an external operator; it NEVER runs LDAP I/O or cutover.
All claim/finish transitions and audit events share one SQLite transaction.
"""
import sqlite3
from ldaps_supervised_recovery import SupervisedRecovery, _identifier
from directory_sync_journal import digest

class DispatchError(ValueError): pass

class RecoveryDispatcher:
    def __init__(self, coordinator):
        self.coordinator=coordinator
        self.db=coordinator.db
        self.review=SupervisedRecovery(coordinator)
        self.db.execute("""CREATE TABLE IF NOT EXISTS ldaps_recovery_dispatch (
          new_event_id TEXT PRIMARY KEY, review_id TEXT NOT NULL UNIQUE,
          state TEXT NOT NULL CHECK(state IN ('CLAIMED','FINISHED','ABORTED')),
          owner TEXT NOT NULL, epoch INTEGER NOT NULL, claimed_at INTEGER NOT NULL,
          finished_at INTEGER, record_hash TEXT NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS ldaps_recovery_dispatch_events (
          seq INTEGER PRIMARY KEY, new_event_id TEXT NOT NULL, action TEXT NOT NULL,
          owner TEXT NOT NULL, epoch INTEGER NOT NULL, at INTEGER NOT NULL,
          previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)""")

    def _verify(self):
        self.review.verify()
        previous='0'*64
        rows=self.db.execute('SELECT seq,new_event_id,action,owner,epoch,at,previous_hash,event_hash FROM ldaps_recovery_dispatch_events ORDER BY seq').fetchall()
        for index,(seq,event_id,action,owner,epoch,at,ph,h) in enumerate(rows,1):
            record=dict(seq=seq,new_event_id=event_id,action=action,owner=owner,epoch=epoch,at=at,previous_hash=ph)
            if seq!=index or ph!=previous or digest(record)!=h: raise DispatchError('EVENT_CHAIN_TAMPERED')
            previous=h
        states={}
        for seq,event_id,action,owner,epoch,at,ph,h in rows:
            if action=='CLAIM':
                if event_id in states or epoch!=1:raise DispatchError('INVALID_EVENT_HISTORY')
                states[event_id]=('CLAIMED',owner,epoch,at,None)
            elif action in ('FINISH','ABORT'):
                old=states.get(event_id)
                if not old or old[0]!='CLAIMED' or (owner,epoch)!=(old[1],old[2]) or at<old[3]:raise DispatchError('INVALID_EVENT_HISTORY')
                states[event_id]=('FINISHED' if action=='FINISH' else 'ABORTED',owner,epoch,old[3],at)
            else:raise DispatchError('INVALID_EVENT_ACTION')
        records=self.db.execute('SELECT new_event_id,review_id,state,owner,epoch,claimed_at,finished_at,record_hash FROM ldaps_recovery_dispatch').fetchall()
        if len(records)!=len(states):raise DispatchError('DISPATCH_STATE_TAMPERED')
        for event_id,review_id,state,owner,epoch,claimed,finished,h in records:
            obj=dict(new_event_id=event_id,review_id=review_id,state=state,owner=owner,epoch=epoch,claimed_at=claimed,finished_at=finished)
            if digest(obj)!=h or states.get(event_id)!=(state,owner,epoch,claimed,finished):raise DispatchError('DISPATCH_STATE_TAMPERED')
            review=self.db.execute('SELECT new_event_id,decision FROM ldaps_recovery_reviews WHERE review_id=?',(review_id,)).fetchone()
            if review!=(event_id,'APPROVE_NEW_ATTEMPT'):raise DispatchError('REVIEW_BINDING_TAMPERED')
        return len(records)

    def verify(self):
        return dict(status='LOCAL_HASHES_VERIFIED_NOT_AUTHENTICATED',count=self._verify(),cutover_authorized=False)

    def _event(self,event_id,action,owner,epoch,at):
        last=self.db.execute('SELECT seq,event_hash FROM ldaps_recovery_dispatch_events ORDER BY seq DESC LIMIT 1').fetchone()
        seq=last[0]+1 if last else 1
        obj=dict(seq=seq,new_event_id=event_id,action=action,owner=owner,epoch=epoch,at=at,previous_hash=last[1] if last else '0'*64)
        self.db.execute('INSERT INTO ldaps_recovery_dispatch_events VALUES (?,?,?,?,?,?,?,?)',(seq,event_id,action,owner,epoch,at,obj['previous_hash'],digest(obj)))

    def claim(self, *, review_id, owner, at):
        _identifier(review_id);_identifier(owner)
        if type(at)!=int or at<0:raise DispatchError('INVALID_TIME')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self._verify()
            row=self.db.execute('SELECT new_event_id,decision,reviewed_at FROM ldaps_recovery_reviews WHERE review_id=?',(review_id,)).fetchone()
            if not row or row[1]!='APPROVE_NEW_ATTEMPT' or not row[0]:raise DispatchError('NO_APPROVED_RESERVATION')
            event_id,_,reviewed_at=row
            if at<reviewed_at:raise DispatchError('TIME_BEFORE_REVIEW')
            if self.db.execute('SELECT 1 FROM ldaps_recovery_dispatch WHERE new_event_id=? OR review_id=?',(event_id,review_id)).fetchone():raise DispatchError('ALREADY_CONSUMED')
            if self.db.execute('SELECT 1 FROM ldaps_attempt_intents WHERE event_id=?',(event_id,)).fetchone() or self.db.execute('SELECT 1 FROM directory_sync_events WHERE event_id=?',(event_id,)).fetchone():raise DispatchError('EVENT_ALREADY_EXISTS')
            obj=dict(new_event_id=event_id,review_id=review_id,state='CLAIMED',owner=owner,epoch=1,claimed_at=at,finished_at=None)
            self.db.execute('INSERT INTO ldaps_recovery_dispatch VALUES (?,?,?,?,?,?,?,?)',(event_id,review_id,'CLAIMED',owner,1,at,None,digest(obj)))
            self._event(event_id,'CLAIM',owner,1,at)
            self.db.commit()
            return dict(status='CLAIMED_NOT_EXECUTED',new_event_id=event_id,owner=owner,epoch=1,cutover_authorized=False,automatic_retry=False)
        except BaseException:
            self.db.rollback();raise

    def finish(self, *, new_event_id, owner, epoch, at, outcome):
        _identifier(new_event_id);_identifier(owner)
        if type(epoch)!=int or epoch!=1 or type(at)!=int or at<0 or outcome not in ('FINISH','ABORT'):raise DispatchError('INVALID_TRANSITION')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self._verify()
            row=self.db.execute('SELECT review_id,state,owner,epoch,claimed_at FROM ldaps_recovery_dispatch WHERE new_event_id=?',(new_event_id,)).fetchone()
            if not row or row[1]!='CLAIMED' or row[2]!=owner or row[3]!=epoch or at<row[4]:raise DispatchError('STALE_OR_INVALID_OWNER')
            review_id=row[0];state='FINISHED' if outcome=='FINISH' else 'ABORTED'
            obj=dict(new_event_id=new_event_id,review_id=review_id,state=state,owner=owner,epoch=epoch,claimed_at=row[4],finished_at=at)
            self.db.execute('UPDATE ldaps_recovery_dispatch SET state=?,finished_at=?,record_hash=? WHERE new_event_id=?',(state,at,digest(obj),new_event_id))
            self._event(new_event_id,outcome,owner,epoch,at)
            self.db.commit()
            return dict(status=state,cutover_authorized=False,automatic_retry=False)
        except BaseException:
            self.db.rollback();raise
