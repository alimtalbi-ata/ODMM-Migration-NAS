"""Fail-closed RBAC and independent dual review for uncertain outcomes.

Local identity grants are administrative test data, not external authentication.
No review decision triggers execution or cutover.
"""
from directory_sync_journal import digest

class ReconciliationRBACError(ValueError): pass

class ReconciliationRBAC:
    ROLES = {'SECURITY', 'OPERATIONS'}
    ACTIONS = {'INVESTIGATE','ACKNOWLEDGE','BLOCK'}
    CRITICAL = {'TARGET_COMMITTED_RECEIPT_MISSING','RECEIPT_WITHOUT_TARGET','EVIDENCE_MISMATCH','NOT_APPLIED'}

    def __init__(self, reconciliation):
        self.rec = reconciliation
        self.db = reconciliation.db
        self.db.execute("""CREATE TABLE IF NOT EXISTS ldaps_rbac_users (
            reviewer TEXT PRIMARY KEY, role TEXT NOT NULL, active INTEGER NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS ldaps_rbac_decisions (
            seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL, request_id TEXT NOT NULL,
            observation_hash TEXT NOT NULL, reviewer TEXT NOT NULL, role TEXT NOT NULL,
            action TEXT NOT NULL, decided_at INTEGER NOT NULL,
            previous_hash TEXT NOT NULL, evidence_hash TEXT NOT NULL,
            UNIQUE(event_id,request_id,observation_hash,reviewer))""")

    def set_reviewer(self, reviewer, role, *, active):
        if not isinstance(reviewer,str) or not reviewer.strip() or len(reviewer)>128 or role not in self.ROLES or type(active)!=bool:
            raise ReconciliationRBACError('INVALID_GRANT')
        self.db.execute('INSERT INTO ldaps_rbac_users VALUES (?,?,?) ON CONFLICT(reviewer) DO UPDATE SET role=excluded.role,active=excluded.active', (reviewer.strip(),role,int(active)))

    def verify(self):
        prev='GENESIS'; rows=self.db.execute('SELECT * FROM ldaps_rbac_decisions ORDER BY seq').fetchall()
        for seq,event,request,obs,reviewer,role,action,at,old,h in rows:
            obj=dict(seq=seq,event_id=event,request_id=request,observation_hash=obs,reviewer=reviewer,role=role,action=action,decided_at=at,previous_hash=prev)
            if old!=prev or digest(obj)!=h:raise ReconciliationRBACError('RBAC_AUDIT_TAMPERED')
            prev=h
        return {'count':len(rows),'last_hash':prev}

    def decide(self,event_id,request_id,*,observation_hash,reviewer,action,decided_at,max_age_seconds=3600, _external_anchor=None):
        if not isinstance(reviewer,str) or not reviewer.strip() or action not in self.ACTIONS or type(decided_at)!=int or decided_at<0 or type(max_age_seconds)!=int or max_age_seconds<0:
            raise ReconciliationRBACError('INVALID_DECISION')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.rec.verify();self.verify()
            if _external_anchor is not None:
                from ldaps_anchored_gate import verify_anchored_startup
                verify_anchored_startup(self, now=decided_at,
                    anchor_path=_external_anchor[0], key=_external_anchor[1])
            # Strict mode is persistent and rejects missing or stale audited policies.
            from ldaps_strict_security import StrictSecurityMode
            StrictSecurityMode(self).guard(now=decided_at)
            bridge_exists=self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ldaps_rbac_grant_audit'").fetchone()
            if bridge_exists:
                from ldaps_directory_rbac_bridge import DirectoryRBACBridge
                DirectoryRBACBridge(self).verify()
            policy_audit_exists=self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ldaps_freshness_policy_audit'").fetchone()
            if policy_audit_exists:
                # Enforce the startup security gate on every audited human decision.
                # The gate is read-only and runs inside the decision write lock.
                from ldaps_security_startup import verify_startup
                initialized=self.db.execute('SELECT 1 FROM ldaps_freshness_policy_audit LIMIT 1').fetchone()
                if initialized:
                    verify_startup(self, now=decided_at, require_audited_policy=True)
            freshness_table=self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ldaps_rbac_directory_freshness'").fetchone()
            if freshness_table:
                policy=self.db.execute('SELECT synced_at,max_age_seconds FROM ldaps_rbac_directory_freshness WHERE id=1').fetchone()
                if policy is not None:
                    synced,limit=policy
                    if synced<0 or limit<0 or decided_at<synced or decided_at-synced>limit:
                        raise ReconciliationRBACError('DIRECTORY_SNAPSHOT_STALE_FAIL_CLOSED')
            grant=self.db.execute('SELECT role,active FROM ldaps_rbac_users WHERE reviewer=?',(reviewer.strip(),)).fetchone()
            if not grant or not grant[1]:raise ReconciliationRBACError('REVIEWER_NOT_AUTHORIZED')
            role=grant[0]
            row=self.db.execute('SELECT observed_at,state,target_hash,local_hash,evidence_hash FROM ldaps_crash_reconciliations WHERE event_id=? AND request_id=? ORDER BY seq DESC LIMIT 1',(event_id,request_id)).fetchone()
            if not row or row[4]!=observation_hash:raise ReconciliationRBACError('STALE_OBSERVATION')
            at,state,target,local,_=row
            if at>decided_at or decided_at-at>max_age_seconds:raise ReconciliationRBACError('EXPIRED_OBSERVATION')
            if state=='CONSISTENT':raise ReconciliationRBACError('NO_UNCERTAINTY')
            invalidations_exist=self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ldaps_rbac_review_invalidations'").fetchone()
            if invalidations_exist and self.db.execute('SELECT 1 FROM ldaps_rbac_review_invalidations WHERE event_id=? AND request_id=? AND observation_hash=?',(event_id,request_id,observation_hash)).fetchone():
                raise ReconciliationRBACError('REVIEW_INVALIDATED_BY_DIRECTORY_CHANGE')
            live=self.rec.inspect(event_id,request_id)
            if (live['state'],live['target_hash'],live['local_hash'])!=(state,target,local):raise ReconciliationRBACError('EVIDENCE_CHANGED')
            prior=self.db.execute('SELECT reviewer,role,action FROM ldaps_rbac_decisions WHERE event_id=? AND request_id=? AND observation_hash=?',(event_id,request_id,observation_hash)).fetchall()
            if any(a!=action for _,_,a in prior):raise ReconciliationRBACError('CONFLICTING_DECISIONS')
            if any(r==reviewer.strip() for r,_,_ in prior):raise ReconciliationRBACError('DUPLICATE_REVIEWER')
            if state in self.CRITICAL and any(r==role for _,r,_ in prior):raise ReconciliationRBACError('INDEPENDENT_ROLE_REQUIRED')
            if state in self.CRITICAL and len(prior)>=2:raise ReconciliationRBACError('ALREADY_REVIEWED')
            last=self.db.execute('SELECT seq,evidence_hash FROM ldaps_rbac_decisions ORDER BY seq DESC LIMIT 1').fetchone()
            seq=last[0]+1 if last else 1;prev=last[1] if last else 'GENESIS'
            obj=dict(seq=seq,event_id=event_id,request_id=request_id,observation_hash=observation_hash,reviewer=reviewer.strip(),role=role,action=action,decided_at=decided_at,previous_hash=prev)
            h=digest(obj)
            self.db.execute('INSERT INTO ldaps_rbac_decisions VALUES (?,?,?,?,?,?,?,?,?,?)',(seq,event_id,request_id,observation_hash,reviewer.strip(),role,action,decided_at,prev,h))
            approved=(state not in self.CRITICAL or len(prior)==1)
            self.db.execute('COMMIT')
            return {'status':'DUAL_REVIEW_COMPLETE' if approved and state in self.CRITICAL else ('REVIEW_RECORDED' if approved else 'SECOND_INDEPENDENT_REVIEW_REQUIRED'), 'review_complete':approved,'execution_authorized':False,'cutover_authorized':False,'automatic_retry':False,'evidence_sha256':h}
        except BaseException:
            self.db.execute('ROLLBACK');raise
