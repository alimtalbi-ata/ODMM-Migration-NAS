"""Conservative cross-evidence gate. Offline observations do not certify NAS access."""
import hashlib
import json
from effective_access_compare import verify_comparison, AccessComparisonError
from group_membership_compare import verify_group_comparison, GroupComparisonError
from collector_evidence_bridge import verify_bridge, BridgeError

class PrivilegeGateError(ValueError): pass

def _digest(report):
    return hashlib.sha256(json.dumps(report,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()

def assess_privilege_evidence(group_bundle, group_inputs, access_bundle, source_acl, target_acl):
    if not isinstance(group_inputs,(tuple,list)) or len(group_inputs)!=5:
        raise PrivilegeGateError('INVALID_GROUP_INPUTS')
    try:
        verify_group_comparison(group_bundle,*group_inputs)
        verify_comparison(access_bundle)
        verify_bridge(source_acl)
        verify_bridge(target_acl)
    except (GroupComparisonError,AccessComparisonError,BridgeError,TypeError,KeyError,ValueError) as exc:
        raise PrivilegeGateError('UNVERIFIED_EVIDENCE') from exc
    left,right=source_acl['report'],target_acl['report']
    if left['protocol']!=right['protocol'] or left['vendor']!=right['vendor']:
        raise PrivilegeGateError('INCOMPATIBLE_ACL_PROFILES')
    group_report=group_bundle['report']; access=access_bundle['report']
    if access['protocol']!=left['protocol']:
        raise PrivilegeGateError('ACCESS_PROTOCOL_MISMATCH')
    drift=group_report['status']=='BLOCKED' or any(f['status']=='BLOCKED_PRIVILEGE_DRIFT' for f in group_report['findings'])
    mismatch=access['summary']['MISMATCH']>0
    incomplete=(any(f['status']!='DECLARED_MATCH_ONLY' for f in group_report['findings'])
                or bool(group_report['unmatched_target_users'])
                or access['summary']['INDETERMINATE']>0
                or not access['findings'])
    status='BLOCKED_PRIVILEGE_DRIFT' if drift or mismatch else 'INDETERMINATE_EVIDENCE' if incomplete else 'PENDING_LIVE_VERIFICATION'
    report={'schema':'odmm.privilege-evidence-gate.v1','status':status,
            'protocol':left['protocol'],'vendor':left['vendor'],
            'evidence_hashes':{'groups':group_bundle['sha256'],'access':access_bundle['sha256'],
                               'source_acl':source_acl['sha256'],'target_acl':target_acl['sha256']},
            'group_drift':drift,'access_mismatch':mismatch,'incomplete':incomplete,
            'manual_review_required':True,'production_qualified':False,'cutover_authorized':False,
            'limitations':['OFFLINE_UNAUTHENTICATED_EVIDENCE','ACL_CONTENT_NOT_COMPARED',
                           'IDENTITY_ALIAS_NOT_DIRECTORY_VERIFIED','NO_LIVE_NAS_QUALIFICATION']}
    return {'report':report,'sha256':_digest(report)}

def verify_privilege_assessment(bundle,*args):
    if not isinstance(bundle,dict) or bundle!=assess_privilege_evidence(*args):
        raise PrivilegeGateError('REPORT_MISMATCH')
    return True
