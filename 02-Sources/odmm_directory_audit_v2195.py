"""Fail-closed anchored audit for directory/campaign reconciliation.
Author: Abdelhalim Talbi. Not proof of authenticated NAS access.
"""
from odmm_authenticated_campaign_v2194 import reconcile_directory_campaign
from odmm_access_audit_v2184 import digest, AuditError
from odmm_access_anchor_v2185 import append_anchored

def audit_directory_campaign(directory, campaign, identity_to_dn, group_to_dn, *, now, audit_path, anchor_path, expected_head=None, max_age=300):
    result = reconcile_directory_campaign(directory, campaign, identity_to_dn, group_to_dn, now=now, max_age=max_age)
    report = result['report']
    if digest(report) != result['sha256']:
        raise AuditError('RECONCILIATION_DIGEST_MISMATCH')
    cases = report['cases']
    if not cases or len(cases) > 1000 or len({c['case_id'] for c in cases}) != len(cases):
        raise AuditError('INVALID_CASE_SCOPE')
    summary = {
        'schema':'odmm.directory-audit.v2195',
        'directory_sha256':result['report']['directory_sha256'],
        'campaign_sha256':result['report']['campaign_sha256'],
        'reconciliation_sha256':result['sha256'],
        'cases': [{'case_id':c['case_id'], 'identity_ref':c['identity_ref'],
                   'groups_equal':c['groups_equal'], 'local_access_equal':c['local_access_equal']} for c in cases],
        'group_mismatch_count':report['group_mismatch_count'],
        'cutover_authorized':False,
        'nas_qualified':False,
        'dedicated_account_attested':False,
        'nas_effective_access_verified':False,
        'limitations':['DIRECTORY_CLAIMS_NOT_NAS_AUTHENTICATION','NO_PHYSICAL_NAS_QUALIFICATION'],
    }
    evidence={'report':summary,'sha256':digest(summary)}
    entry=append_anchored(audit_path,anchor_path,evidence,expected_head=expected_head)
    return {'evidence':evidence,'audit':entry,'cutover_authorized':False}
