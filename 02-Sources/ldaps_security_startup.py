"""Read-only startup gate for audited directory freshness policies.

Checks SQLite structural integrity and audit chain. Does not authenticate users,
protect against a privileged DB administrator, or authorize external effects.
"""
from ldaps_freshness_policy_audit import AuditedFreshnessPolicy
from ldaps_directory_freshness import DirectoryFreshnessPolicy
from ldaps_rbac_reconciliation import ReconciliationRBACError


def verify_startup(rbac, *, now, require_audited_policy=True):
    if type(now) is not int or now < 0:
        raise ReconciliationRBACError('INVALID_TIMESTAMP')
    db=rbac.db
    integrity=db.execute('PRAGMA integrity_check').fetchone()
    if not integrity or integrity[0] != 'ok':
        raise ReconciliationRBACError('SQLITE_INTEGRITY_FAILED')
    tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if require_audited_policy and 'ldaps_freshness_policy_audit' not in tables:
        raise ReconciliationRBACError('AUDITED_POLICY_REQUIRED')
    if 'ldaps_freshness_policy_audit' in tables:
        evidence=AuditedFreshnessPolicy(rbac).verify()
        if require_audited_policy and evidence['events']==0:
            raise ReconciliationRBACError('AUDITED_POLICY_NOT_INITIALIZED')
    state=DirectoryFreshnessPolicy(rbac).assess(now=now)
    if state['status'] != 'FRESH' or not state['review_allowed']:
        raise ReconciliationRBACError('DIRECTORY_POLICY_NOT_FRESH')
    return {'status':'STARTUP_SECURITY_CHECK_PASSED', 'directory_status':'FRESH',
            'review_allowed':True, 'execution_authorized':False,
            'cutover_authorized':False, 'production_qualified':False}
