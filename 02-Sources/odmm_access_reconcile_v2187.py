"""Fail-closed reconciliation of isolated source/target access observations.
No claim of authenticated NAS authorization. Author: Abdelhalim Talbi.
"""
from odmm_access_audit_v2184 import AuditError, digest
from odmm_access_anchor_v2185 import append_anchored

SCHEMA='odmm.access-reconciliation.v2187'

def reconcile_campaign(campaign):
    if not isinstance(campaign,dict) or set(campaign)!={'report','sha256'}:
        raise AuditError('INVALID_CAMPAIGN')
    report=campaign['report']
    if not isinstance(report,dict) or digest(report)!=campaign['sha256'] or report.get('schema')!='odmm.isolated-access-campaign.v2183':
        raise AuditError('INVALID_CAMPAIGN_DIGEST')
    if report.get('cutover_authorized') is not False or report.get('nas_qualified') is not False or report.get('dedicated_account_attested') is not False:
        raise AuditError('UNTRUSTED_CAMPAIGN')
    cases=report.get('cases')
    if not isinstance(cases,list) or not cases or len(cases)>100:
        raise AuditError('INVALID_CASES')
    seen=set(); outcomes=[]
    for item in cases:
        if not isinstance(item,dict) or set(item)!={'report','sha256'} or not isinstance(item['report'],dict) or digest(item['report'])!=item['sha256']:
            raise AuditError('INVALID_CASE_EVIDENCE')
        r=item['report']; cid=r.get('case_id')
        if not isinstance(cid,str) or not cid or cid in seen:
            raise AuditError('DUPLICATE_OR_INVALID_CASE')
        seen.add(cid)
        if r.get('cutover_authorized') is not False or not isinstance(r.get('local_open_outcomes_equal'),bool):
            raise AuditError('UNTRUSTED_CASE')
        if r.get('execution_euid')!=report.get('execution_euid') or r.get('execution_egid')!=report.get('execution_egid'):
            raise AuditError('IDENTITY_MISMATCH')
        outcomes.append({'case_id':cid,'equal':r['local_open_outcomes_equal'],'evidence_sha256':item['sha256']})
    if report.get('all_local_outcomes_equal') is not all(x['equal'] for x in outcomes):
        raise AuditError('INCONSISTENT_CAMPAIGN_SUMMARY')
    result={'schema':SCHEMA,'cases':outcomes,'all_local_outcomes_equal':all(x['equal'] for x in outcomes),
            'source_campaign_sha256':campaign['sha256'],'nas_qualified':False,'cutover_authorized':False,'dedicated_account_attested':False,
            'limitations':['LOCAL_OS_ONLY','NO_REMOTE_AD_LDAP_AUTHENTICATION','NO_NAS_CERTIFICATION']}
    return {'report':result,'sha256':digest(result)}

def reconcile_and_audit(campaign,audit_path,anchor_path,*,expected_head=None):
    evidence=reconcile_campaign(campaign)
    entry=append_anchored(audit_path,anchor_path,evidence,expected_head=expected_head)
    return {'evidence':evidence,'audit':entry,'cutover_authorized':False}
