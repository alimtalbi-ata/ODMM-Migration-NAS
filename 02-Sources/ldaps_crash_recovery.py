"""Durable LDAPS attempt intents and fail-closed post-crash reconciliation.

The intent is committed before network I/O. The successful RBAC/quarantine/event
commit is delegated to sync_atomically. Recovery never replays network writes.
"""
import re
import sqlite3
from directory_sync_journal import DirectorySyncJournal
from ldaps_atomic_journal_pipeline import sync_atomically

class CrashRecoveryError(ValueError): pass

class CrashRecoveryCoordinator:
    def __init__(self, ledger):
        self.ledger=ledger
        self.db=ledger.db
        self.journal=DirectorySyncJournal(self.db)
        self.db.execute('''CREATE TABLE IF NOT EXISTS ldaps_attempt_intents (
            event_id TEXT PRIMARY KEY, started_at INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('STARTED','COMMITTED','INTERRUPTED','FAILED')),
            detail TEXT NOT NULL DEFAULT '')''')

    def begin(self,event_id,now):
        if not isinstance(event_id,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',event_id):
            raise CrashRecoveryError('INVALID_EVENT_ID')
        if type(now) is not int or now<0: raise CrashRecoveryError('INVALID_TIME')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.journal._verify_locked()
            if self.db.execute('SELECT 1 FROM directory_sync_events WHERE event_id=?',(event_id,)).fetchone():
                raise CrashRecoveryError('ALREADY_JOURNALED')
            self.db.execute('INSERT INTO ldaps_attempt_intents(event_id,started_at,state) VALUES (?, ?, ?)',(event_id,now,'STARTED'))
            self.db.commit()
        except sqlite3.IntegrityError as e:
            self.db.rollback();raise CrashRecoveryError('DUPLICATE_INTENT') from e
        except BaseException:
            self.db.rollback();raise

    def _finish(self,event_id,state,detail=''):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.journal._verify_locked()
            row=self.db.execute('SELECT state FROM ldaps_attempt_intents WHERE event_id=?',(event_id,)).fetchone()
            if row != ('STARTED',): raise CrashRecoveryError('INVALID_INTENT_STATE')
            self.db.execute('UPDATE ldaps_attempt_intents SET state=?,detail=? WHERE event_id=?',(state,detail,event_id))
            self.db.commit()
        except BaseException:
            self.db.rollback();raise

    def run(self,*,event_id,now,**kwargs):
        self.begin(event_id,now)
        try:
            result=sync_atomically(self.ledger,event_id=event_id,now=now,journal=self.journal,**kwargs)
        except Exception:
            # A failed collection may itself be journaled; reconciliation resolves
            # both cases, without claiming that a failed attempt succeeded.
            self.reconcile()
            raise
        self._finish(event_id,'COMMITTED')
        return {**result,'attempt_state':'COMMITTED'}

    def reconcile(self):
        """Classify pending attempts using durable journal; never retry imports."""
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.journal._verify_locked()
            pending=self.db.execute("SELECT event_id FROM ldaps_attempt_intents WHERE state='STARTED' ORDER BY event_id").fetchall()
            outcomes=[]
            for (event_id,) in pending:
                record=self.db.execute('SELECT status FROM directory_sync_events WHERE event_id=?',(event_id,)).fetchone()
                if record and record[0]=='SUCCESS': state='COMMITTED';detail='SUCCESS_EVENT_PRESENT'
                elif record: state='FAILED';detail='FAILURE_EVENT_PRESENT'
                else: state='INTERRUPTED';detail='NO_DURABLE_EVENT'
                self.db.execute('UPDATE ldaps_attempt_intents SET state=?,detail=? WHERE event_id=?',(state,detail,event_id))
                outcomes.append({'event_id':event_id,'state':state,'detail':detail,'cutover_authorized':False})
            self.db.commit()
            return outcomes
        except BaseException:
            self.db.rollback();raise

    def inspect(self,event_id):
        row=self.db.execute('SELECT state,detail FROM ldaps_attempt_intents WHERE event_id=?',(event_id,)).fetchone()
        return {'state':row[0],'detail':row[1],'cutover_authorized':False} if row else None
