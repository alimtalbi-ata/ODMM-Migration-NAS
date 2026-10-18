"""Fail-closed human review of uncertain simulated target outcomes.

A decision never executes a retry or authorizes a cutover.
"""
from directory_sync_journal import digest
from ldaps_crash_reconciliation import CrashReconciliationError

class UncertainReviewError(ValueError): pass

class UncertainReviewLedger:
    ACTIONS = {'INVESTIGATE','ACKNOWLEDGE','BLOCK'}
    def __init__(self, reconciliation):
        self.reconciliation = reconciliation
        self.db = reconciliation.db
        self.db.execute("""CREATE TABLE IF NOT EXISTS ldaps_uncertain_reviews (
            seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL, request_id TEXT NOT NULL,
            observation_hash TEXT NOT NULL, reviewer TEXT NOT NULL, action TEXT NOT NULL,
            decided_at INTEGER NOT NULL, previous_hash TEXT NOT NULL, evidence_hash TEXT NOT NULL,
            UNIQUE(event_id,request_id,observation_hash))""")

    def verify(self):
        previous='GENESIS'
        rows=self.db.execute('SELECT seq,event_id,request_id,observation_hash,reviewer,action,decided_at,previous_hash,evidence_hash FROM ldaps_uncertain_reviews ORDER BY seq').fetchall()
        for seq,event_id,request_id,obs,reviewer,action,at,prev,h in rows:
            obj=dict(seq=seq,event_id=event_id,request_id=request_id,observation_hash=obs,reviewer=reviewer,action=action,decided_at=at,previous_hash=previous)
            if prev!=previous or digest(obj)!=h:raise UncertainReviewError('REVIEW_AUDIT_TAMPERED')
            previous=h
        return {'count':len(rows),'last_hash':previous}

    def decide(self,event_id,request_id,*,observation_hash,reviewer,action,decided_at,max_age_seconds=3600):
        if not isinstance(reviewer,str) or not reviewer.strip() or len(reviewer)>128:raise UncertainReviewError('INVALID_REVIEWER')
        if action not in self.ACTIONS:raise UncertainReviewError('INVALID_ACTION')
        if type(decided_at)!=int or decided_at<0 or type(max_age_seconds)!=int or max_age_seconds<0:raise UncertainReviewError('INVALID_TIME')
        if not isinstance(observation_hash,str) or len(observation_hash)!=64:raise UncertainReviewError('INVALID_OBSERVATION_HASH')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.reconciliation.verify()
            self.verify()
            row=self.db.execute("""SELECT observed_at,state,evidence_hash FROM ldaps_crash_reconciliations
                WHERE event_id=? AND request_id=? ORDER BY seq DESC LIMIT 1""",(event_id,request_id)).fetchone()
            if row is None or row[2]!=observation_hash:raise UncertainReviewError('STALE_OBSERVATION')
            at,state,_=row
            if at>decided_at or decided_at-at>max_age_seconds:raise UncertainReviewError('EXPIRED_OBSERVATION')
            if state=='CONSISTENT':raise UncertainReviewError('NO_UNCERTAINTY_TO_REVIEW')
            # Compare live evidence against the persisted observation. No distributed snapshot guarantee.
            current=self.reconciliation.inspect(event_id,request_id)
            observed=self.db.execute("""SELECT state,target_hash,local_hash FROM ldaps_crash_reconciliations
                WHERE event_id=? AND request_id=? ORDER BY seq DESC LIMIT 1""",(event_id,request_id)).fetchone()
            if (current['state'],current['target_hash'],current['local_hash'])!=observed:raise UncertainReviewError('EVIDENCE_CHANGED')
            last=self.db.execute('SELECT seq,evidence_hash FROM ldaps_uncertain_reviews ORDER BY seq DESC LIMIT 1').fetchone()
            seq=last[0]+1 if last else 1;prev=last[1] if last else 'GENESIS'
            obj=dict(seq=seq,event_id=event_id,request_id=request_id,observation_hash=observation_hash,reviewer=reviewer.strip(),action=action,decided_at=decided_at,previous_hash=prev)
            h=digest(obj)
            self.db.execute('INSERT INTO ldaps_uncertain_reviews VALUES (?,?,?,?,?,?,?,?,?)',(seq,event_id,request_id,observation_hash,reviewer.strip(),action,decided_at,prev,h))
            self.db.execute('COMMIT')
            return {'status':'HUMAN_REVIEW_RECORDED','evidence_sha256':h,'automatic_retry':False,'cutover_authorized':False,'execution_authorized':False}
        except BaseException:
            self.db.execute('ROLLBACK')
            raise
