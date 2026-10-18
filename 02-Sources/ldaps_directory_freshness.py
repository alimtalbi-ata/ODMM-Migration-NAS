"""Optional fail-closed age policy for offline RBAC directory snapshots.

The timestamp is an operator-supplied observation time, not proof of live AD state.
"""
from ldaps_rbac_reconciliation import ReconciliationRBACError
from ldaps_directory_rbac_bridge import DirectoryRBACBridge

class DirectoryFreshnessPolicy:
    def __init__(self, rbac):
        self.rbac=rbac
        self.db=rbac.db
        DirectoryRBACBridge(rbac)

    def configure(self, *, max_age_seconds):
        if type(max_age_seconds)!=int or max_age_seconds<0:
            raise ReconciliationRBACError('INVALID_DIRECTORY_MAX_AGE')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            # Legacy configuration must never bypass an installed audited policy.
            audit_table=self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ldaps_freshness_policy_audit'").fetchone()
            if audit_table:
                from ldaps_freshness_policy_audit import AuditedFreshnessPolicy
                AuditedFreshnessPolicy(self.rbac).verify()
                raise ReconciliationRBACError('AUDITED_POLICY_REQUIRED')
            row=self.db.execute('SELECT snapshot_hash FROM ldaps_rbac_directory_versions WHERE id=1').fetchone()
            if not row:
                raise ReconciliationRBACError('DIRECTORY_SNAPSHOT_REQUIRED')
            DirectoryRBACBridge(self.rbac).verify()
            self.rbac.verify()
            audit=self.db.execute('SELECT at FROM ldaps_rbac_grant_audit ORDER BY seq DESC LIMIT 1').fetchone()
            if not audit:raise ReconciliationRBACError('DIRECTORY_AUDIT_REQUIRED')
            self.db.execute('INSERT INTO ldaps_rbac_directory_freshness VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET synced_at=excluded.synced_at,max_age_seconds=excluded.max_age_seconds',(audit[0],max_age_seconds))
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
        return {'status':'FRESHNESS_POLICY_ENABLED','max_age_seconds':max_age_seconds,'execution_authorized':False,'cutover_authorized':False}

    def assess(self, *, now):
        if type(now)!=int or now<0:raise ReconciliationRBACError('INVALID_TIMESTAMP')
        DirectoryRBACBridge(self.rbac).verify()
        audit_table=self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ldaps_freshness_policy_audit'").fetchone()
        if audit_table:
            from ldaps_freshness_policy_audit import AuditedFreshnessPolicy
            AuditedFreshnessPolicy(self.rbac).verify()
        row=self.db.execute('SELECT synced_at,max_age_seconds FROM ldaps_rbac_directory_freshness WHERE id=1').fetchone()
        if row is None:return {'status':'NOT_CONFIGURED','review_allowed':False}
        synced,limit=row
        return {'status':'FRESH' if synced<=now<=synced+limit else 'STALE', 'review_allowed':synced<=now<=synced+limit,'synced_at':synced,'max_age_seconds':limit}
