"""Human-reviewed LDAPS recovery preparation; never executes a retry or cutover.

All decisions and new-attempt reservations are durable and transactional. A review
is bound to a SHA-256 recovery-plan snapshot, not an authentication claim.
"""
import re
import sqlite3
from directory_sync_journal import DirectorySyncJournal, digest
from ldaps_recovery_plan import build_recovery_plan

class SupervisedRecoveryError(ValueError): pass

_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")

def _identifier(value):
    if not isinstance(value,str) or not _ID.fullmatch(value):
        raise SupervisedRecoveryError('INVALID_IDENTIFIER')
    return value

class SupervisedRecovery:
    def __init__(self, coordinator):
        self.coordinator=coordinator
        self.db=coordinator.db
        self.journal=DirectorySyncJournal(self.db)
        self.db.execute("""CREATE TABLE IF NOT EXISTS ldaps_recovery_reviews (
            original_event_id TEXT PRIMARY KEY, review_id TEXT NOT NULL UNIQUE,
            plan_hash TEXT NOT NULL, reviewer TEXT NOT NULL,
            decision TEXT NOT NULL CHECK(decision IN ('APPROVE_NEW_ATTEMPT','REJECT')),
            new_event_id TEXT UNIQUE, reviewed_at INTEGER NOT NULL,
            review_hash TEXT NOT NULL)""")

    def decide(self, *, plan, original_event_id, review_id, reviewer, decision,
               new_event_id=None, now, max_age_seconds):
        for value in (original_event_id,review_id,reviewer): _identifier(value)
        if type(now) is not int or now<0 or type(max_age_seconds) is not int or max_age_seconds<=0:
            raise SupervisedRecoveryError('INVALID_TIME')
        if decision not in ('APPROVE_NEW_ATTEMPT','REJECT'):
            raise SupervisedRecoveryError('INVALID_DECISION')
        if decision=='APPROVE_NEW_ATTEMPT':
            _identifier(new_event_id)
            if new_event_id==original_event_id: raise SupervisedRecoveryError('REUSED_EVENT_ID')
        elif new_event_id is not None: raise SupervisedRecoveryError('UNEXPECTED_NEW_EVENT')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.journal._verify_locked()
            fresh=build_recovery_plan(self.coordinator,now=now,max_age_seconds=max_age_seconds)
            if plan!=fresh: raise SupervisedRecoveryError('STALE_OR_TAMPERED_PLAN')
            match=[x for x in fresh['report']['attempts'] if x['event_id']==original_event_id]
            if len(match)!=1: raise SupervisedRecoveryError('UNKNOWN_ATTEMPT')
            item=match[0]
            if decision=='APPROVE_NEW_ATTEMPT':
                if item['effective_state'] not in ('INTERRUPTED','FAILED') or item['action'] not in ('MANUAL_REVIEW_BEFORE_NEW_ATTEMPT','REVIEW_FAILURE_AND_DIRECTORY_STATE'):
                    raise SupervisedRecoveryError('NOT_ELIGIBLE_FOR_NEW_ATTEMPT')
                if self.db.execute('SELECT 1 FROM ldaps_attempt_intents WHERE event_id=?',(new_event_id,)).fetchone() or self.db.execute('SELECT 1 FROM directory_sync_events WHERE event_id=?',(new_event_id,)).fetchone():
                    raise SupervisedRecoveryError('NEW_EVENT_ALREADY_USED')
            entry={'original_event_id':original_event_id,'review_id':review_id,'reviewer':reviewer,
                   'decision':decision,'new_event_id':new_event_id,'reviewed_at':now,
                   'plan_hash':fresh['sha256'],'cutover_authorized':False,'automatic_retry':False}
            h=digest(entry)
            self.db.execute('INSERT INTO ldaps_recovery_reviews VALUES (?,?,?,?,?,?,?,?)',
                            (original_event_id,review_id,fresh['sha256'],reviewer,decision,new_event_id,now,h))
            self.db.commit()
            return {'review':entry,'sha256':h,'status':'NEW_ATTEMPT_RESERVED_NOT_EXECUTED' if new_event_id else 'REJECTED',
                    'cutover_authorized':False,'automatic_retry':False}
        except sqlite3.IntegrityError as exc:
            self.db.rollback();raise SupervisedRecoveryError('DUPLICATE_REVIEW_OR_RESERVATION') from exc
        except BaseException:
            self.db.rollback();raise

    def verify(self):
        self.journal.verify()
        rows=self.db.execute('SELECT original_event_id,review_id,plan_hash,reviewer,decision,new_event_id,reviewed_at,review_hash FROM ldaps_recovery_reviews ORDER BY original_event_id').fetchall()
        for original,review_id,plan_hash,reviewer,decision,new_event_id,at,h in rows:
            entry={'original_event_id':original,'review_id':review_id,'reviewer':reviewer,
                   'decision':decision,'new_event_id':new_event_id,'reviewed_at':at,
                   'plan_hash':plan_hash,'cutover_authorized':False,'automatic_retry':False}
            if digest(entry)!=h: raise SupervisedRecoveryError('REVIEW_TAMPERED')
        return {'status':'LOCAL_HASHES_VERIFIED_NOT_AUTHENTICATED','count':len(rows),
                'cutover_authorized':False,'automatic_retry':False}
