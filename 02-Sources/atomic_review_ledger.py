"""Atomic dual review + hash-chain journal in one SQLite transaction.
Not identity authentication or cutover authorization.
"""
import time
from dual_review_ledger import DualReviewLedger, ROLES
from human_approval_registry import ApprovalError
from review_event_journal import canonical, event_hash, ReviewEventJournal

class AtomicReviewLedger(DualReviewLedger):
    def __init__(self, path):
        super().__init__(path)
        self.db.execute("""CREATE TABLE IF NOT EXISTS review_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, migration_id TEXT NOT NULL,
            event_json TEXT NOT NULL, prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL UNIQUE)""")

    def _append_in_transaction(self, migration_id, action, actor, evidence_hash, stamp):
        event = dict(migration_id=migration_id, action=action, actor=actor,
                     evidence_hash=evidence_hash, timestamp=stamp)
        prev = self.db.execute('SELECT entry_hash FROM review_events ORDER BY seq DESC LIMIT 1').fetchone()
        previous = prev[0] if prev else '0'*64
        h = event_hash(previous, event)
        self.db.execute('INSERT INTO review_events(migration_id,event_json,prev_hash,entry_hash) VALUES(?,?,?,?)',
                        (migration_id, canonical(event), previous, h))
        return h

    def record(self, migration_id, bundle, role, reviewer, ttl_seconds, *, now=None):
        if role not in ROLES: raise ApprovalError('INVALID_ROLE')
        if any(not isinstance(v,str) or not v.strip() or len(v)>128 for v in (migration_id,reviewer)):
            raise ApprovalError('INVALID_IDENTITY')
        if type(ttl_seconds) is not int or not 1<=ttl_seconds<=86400: raise ApprovalError('INVALID_TTL')
        stamp=int(time.time()) if now is None else now
        if type(stamp) is not int or stamp<0: raise ApprovalError('INVALID_TIME')
        evidence_hash=self._evidence(migration_id,bundle)
        try:
            self.db.execute('BEGIN IMMEDIATE')
            other=self.db.execute('SELECT reviewer,evidence_hash FROM dual_reviews WHERE migration_id=?',(migration_id,)).fetchall()
            if any(r[0]==reviewer for r in other): raise ApprovalError('SEPARATION_OF_DUTIES')
            if any(r[1]!=evidence_hash for r in other): raise ApprovalError('STALE_EVIDENCE')
            self.db.execute('INSERT INTO dual_reviews VALUES (?,?,?,?,?,NULL,?)',
                            (migration_id,role,reviewer,evidence_hash,stamp+ttl_seconds,stamp))
            self._append_in_transaction(migration_id,'REVIEW_RECORDED',reviewer,evidence_hash,stamp)
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
        return {'status':'REVIEW_RECORDED_ONLY','cutover_authorized':False}

    def revoke(self, migration_id, role, *, now=None):
        stamp=int(time.time()) if now is None else now
        if type(stamp) is not int or stamp<0 or role not in ROLES: raise ApprovalError('INVALID_REVOCATION')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            row=self.db.execute('SELECT reviewer,evidence_hash FROM dual_reviews WHERE migration_id=? AND role=? AND revoked_at IS NULL',
                                (migration_id,role)).fetchone()
            if row is None: raise ApprovalError('REVIEW_NOT_ACTIVE')
            self.db.execute('UPDATE dual_reviews SET revoked_at=? WHERE migration_id=? AND role=?',(stamp,migration_id,role))
            self._append_in_transaction(migration_id,'REVIEW_REVOKED',row[0],row[1],stamp)
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
        return {'status':'REVIEW_REVOKED','cutover_authorized':False}

    def verify_journal(self):
        # Uses same connection; do not create a separate journal writer.
        previous='0'*64
        import json
        rows=self.db.execute('SELECT seq,event_json,prev_hash,entry_hash FROM review_events ORDER BY seq').fetchall()
        for expected,(seq,raw,prev,stored) in enumerate(rows,1):
            try:
                event=json.loads(raw)
                valid=canonical(event)==raw and event_hash(previous,event)==stored
            except (ValueError,TypeError): valid=False
            if seq!=expected or prev!=previous or not valid:
                return {'status':'TAMPER_DETECTED','at_seq':seq,'cutover_authorized':False}
            previous=stored
        return {'status':'CHAIN_INTACT_UNAUTHENTICATED','events':len(rows),'head_hash':previous,'cutover_authorized':False}
