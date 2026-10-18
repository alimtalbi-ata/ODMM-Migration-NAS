"""Audited, fail-closed freshness policy changes. Local identities are NOT authenticated.

Policy changes require two distinct active directory reviewers in SECURITY and
OPERATIONS roles; disabling is intentionally unsupported. No execution authority.
"""
from directory_sync_journal import digest
from ldaps_rbac_reconciliation import ReconciliationRBACError
from ldaps_directory_rbac_bridge import DirectoryRBACBridge

class AuditedFreshnessPolicy:
    def __init__(self, rbac):
        self.rbac=rbac; self.db=rbac.db
        DirectoryRBACBridge(rbac)
        self.db.execute('''CREATE TABLE IF NOT EXISTS ldaps_freshness_policy_audit (
            seq INTEGER PRIMARY KEY, at INTEGER NOT NULL, security_reviewer TEXT NOT NULL,
            operations_reviewer TEXT NOT NULL, previous_limit INTEGER, new_limit INTEGER NOT NULL,
            synced_at INTEGER NOT NULL, directory_generation INTEGER NOT NULL,
            previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)''')

    def _verify_locked(self):
        prev='GENESIS'; last_at=-1
        rows=self.db.execute('SELECT * FROM ldaps_freshness_policy_audit ORDER BY seq').fetchall()
        for expected,row in enumerate(rows,1):
            seq,at,sec,ops,old,new,synced,generation,previous,h=row
            payload=dict(seq=seq,at=at,security_reviewer=sec,operations_reviewer=ops,
                         previous_limit=old,new_limit=new,synced_at=synced,
                         directory_generation=generation,previous_hash=prev)
            if seq!=expected or previous!=prev or h!=digest(payload) or at<last_at:
                raise ReconciliationRBACError('FRESHNESS_POLICY_AUDIT_TAMPERED')
            prev=h;last_at=at
        current=self.db.execute('SELECT synced_at,max_age_seconds FROM ldaps_rbac_directory_freshness WHERE id=1').fetchone()
        if rows and (current is None or current[1]!=rows[-1][5]):
            raise ReconciliationRBACError('FRESHNESS_POLICY_STATE_MISMATCH')
        return rows

    def verify(self):
        DirectoryRBACBridge(self.rbac).verify();self.rbac.verify()
        rows=self._verify_locked()
        return {'events':len(rows),'last_hash':rows[-1][-1] if rows else 'GENESIS',
                'execution_authorized':False,'cutover_authorized':False}

    def configure(self, *, max_age_seconds, security_reviewer, operations_reviewer, now):
        if type(max_age_seconds)!=int or max_age_seconds<0 or type(now)!=int or now<0:
            raise ReconciliationRBACError('INVALID_POLICY_PARAMETERS')
        if not all(isinstance(x,str) and x.strip() for x in (security_reviewer,operations_reviewer)) or security_reviewer==operations_reviewer:
            raise ReconciliationRBACError('TWO_DISTINCT_REVIEWERS_REQUIRED')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.verify()
            version=self.db.execute('SELECT generation FROM ldaps_rbac_directory_versions WHERE id=1').fetchone()
            grant_audit=self.db.execute('SELECT at FROM ldaps_rbac_grant_audit ORDER BY seq DESC LIMIT 1').fetchone()
            if not version or not grant_audit:raise ReconciliationRBACError('DIRECTORY_SNAPSHOT_REQUIRED')
            synced=grant_audit[0]
            if synced>now:raise ReconciliationRBACError('FUTURE_DIRECTORY_SNAPSHOT')
            for reviewer,role in ((security_reviewer,'SECURITY'),(operations_reviewer,'OPERATIONS')):
                grant=self.db.execute('SELECT role,active FROM ldaps_rbac_users WHERE reviewer=?',(reviewer,)).fetchone()
                if grant!=(role,1):raise ReconciliationRBACError('POLICY_REVIEWER_NOT_AUTHORIZED')
            current=self.db.execute('SELECT synced_at,max_age_seconds FROM ldaps_rbac_directory_freshness WHERE id=1').fetchone()
            old=current[1] if current else None
            # Reconfiguration never refreshes the directory's observed timestamp.
            preserved=current[0] if current else synced
            last=self.db.execute('SELECT seq,event_hash FROM ldaps_freshness_policy_audit ORDER BY seq DESC LIMIT 1').fetchone()
            seq=last[0]+1 if last else 1;prev=last[1] if last else 'GENESIS'
            last_time=self.db.execute('SELECT at FROM ldaps_freshness_policy_audit ORDER BY seq DESC LIMIT 1').fetchone()
            if last_time and now<last_time[0]:raise ReconciliationRBACError('POLICY_CLOCK_REGRESSION')
            self.db.execute('INSERT INTO ldaps_rbac_directory_freshness VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET max_age_seconds=excluded.max_age_seconds',(preserved,max_age_seconds))
            obj=dict(seq=seq,at=now,security_reviewer=security_reviewer,operations_reviewer=operations_reviewer,
                     previous_limit=old,new_limit=max_age_seconds,synced_at=preserved,
                     directory_generation=version[0],previous_hash=prev)
            h=digest(obj)
            self.db.execute('INSERT INTO ldaps_freshness_policy_audit VALUES (?,?,?,?,?,?,?,?,?,?)',
                            (seq,now,security_reviewer,operations_reviewer,old,max_age_seconds,preserved,version[0],prev,h))
            self.db.execute('COMMIT')
            return {'status':'AUDITED_FRESHNESS_POLICY_ENABLED','event_hash':h,'max_age_seconds':max_age_seconds,
                    'execution_authorized':False,'cutover_authorized':False}
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
