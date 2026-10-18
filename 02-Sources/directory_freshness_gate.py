"""Fail-closed offline directory freshness and reviewer drift assessment.

This is advisory evidence, never a cutover authorization or live AD/LDAP check.
"""
import hashlib
import json
from human_approval_registry import ApprovalError
from directory_snapshot_adapter import normalize_directory_export


def assess_directory_freshness(ledger, export, *, expected_digest, observed_at, now, max_age_seconds=900):
    if not isinstance(expected_digest,str) or len(expected_digest)!=64 or any(c not in '0123456789abcdef' for c in expected_digest):
        raise ApprovalError('INVALID_EXPECTED_DIGEST')
    if any(type(x) is not int for x in (observed_at,now,max_age_seconds)) or observed_at<0 or now<0 or max_age_seconds<=0:
        raise ApprovalError('INVALID_FRESHNESS_WINDOW')
    bundle=normalize_directory_export(export)
    source=bundle['normalized']['source']
    # The snapshot is not authenticated: this report cannot prove actual AD/LDAP state.
    ledger.db.execute('BEGIN IMMEDIATE')
    try:
        row=ledger.db.execute('SELECT version,digest FROM directory_sync_state WHERE source=?',(source,)).fetchone()
        current={r[0]:{'role':r[1],'active':bool(r[2])} for r in ledger.db.execute('SELECT reviewer,role,active FROM reviewer_directory')}
        ledger.db.execute('COMMIT')
    except BaseException:
        if ledger.db.in_transaction: ledger.db.execute('ROLLBACK')
        raise
    proposed={r['reviewer']:{'role':r['role'],'active':r['active']} for r in bundle['normalized']['accounts']}
    changes=[]
    for reviewer in sorted(set(current)|set(proposed)):
        old=current.get(reviewer); new=proposed.get(reviewer)
        if old != new:
            changes.append({'reviewer':reviewer,'previous':old,'proposed':new})
    reasons=[]
    if row is None: reasons.append('NO_APPLIED_SNAPSHOT')
    elif row[1]!=expected_digest: reasons.append('SNAPSHOT_DIGEST_MISMATCH')
    if bundle['sha256']!=expected_digest: reasons.append('EXPORT_DIFFERS_FROM_APPLIED_SNAPSHOT')
    if observed_at>now: reasons.append('FUTURE_OBSERVATION')
    elif now-observed_at>max_age_seconds: reasons.append('SNAPSHOT_EXPIRED')
    if changes: reasons.append('REVIEWER_MEMBERSHIP_DRIFT')
    status='REVIEW_REQUIRED' if reasons else 'OFFLINE_SNAPSHOT_CONSISTENT_NOT_AUTHENTICATED'
    report={'schema':'odmm.directory-freshness.v1','source':source,
        'applied_version':row[0] if row else None,'applied_digest':row[1] if row else None,
        'expected_digest':expected_digest,'candidate_digest':bundle['sha256'],
        'observed_at':observed_at,'now':now,'max_age_seconds':max_age_seconds,
        'status':status,'reasons':reasons,'reviewer_changes':changes,
        'directory_authenticated':False,'cutover_authorized':False,'production_qualified':False}
    digest=hashlib.sha256(json.dumps(report,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'report':report,'sha256':digest}


def verify_directory_freshness(ledger, export, bundle, **kwargs):
    if bundle!=assess_directory_freshness(ledger,export,**kwargs):
        raise ApprovalError('FRESHNESS_REPORT_MISMATCH')
    return True
