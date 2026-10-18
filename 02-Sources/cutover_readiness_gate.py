"""Fail-closed pre-cutover evidence gate; never issues production authorization."""
from acl_ace_compare import _hash
from migration_acl_risk_report import verify_migration_acl_risk, MigrationACLRiskError
from privilege_evidence_gate import verify_privilege_assessment, PrivilegeGateError

class CutoverGateError(ValueError): pass

RECOVERY_STATES = frozenset({'PASS_DECLARED', 'FAIL_DECLARED', 'NOT_TESTED'})

def assess_cutover_readiness(migration_id, datasets, acl_bundle, privilege_bundle,
                             privilege_inputs, recovery_evidence):
    if not isinstance(privilege_inputs, (list, tuple)) or len(privilege_inputs) != 5:
        raise CutoverGateError('INVALID_PRIVILEGE_INPUTS')
    try:
        verify_migration_acl_risk(acl_bundle, migration_id, datasets)
        verify_privilege_assessment(privilege_bundle, *privilege_inputs)
    except (MigrationACLRiskError, PrivilegeGateError, ValueError, TypeError, KeyError) as exc:
        raise CutoverGateError('UNVERIFIED_INPUT_EVIDENCE') from exc
    if not isinstance(recovery_evidence, dict) or set(recovery_evidence) != {'status', 'evidence_ref'}:
        raise CutoverGateError('INVALID_RECOVERY_EVIDENCE')
    recovery_status = recovery_evidence['status']; ref = recovery_evidence['evidence_ref']
    if recovery_status not in RECOVERY_STATES or not isinstance(ref,str) or not ref.strip() or len(ref)>128:
        raise CutoverGateError('INVALID_RECOVERY_EVIDENCE')
    acl_status = acl_bundle['report']['overall_status']
    privilege_status = privilege_bundle['report']['status']
    blocked = (acl_status == 'BLOCKED_POTENTIAL_ACL_LOSS'
               or privilege_status == 'BLOCKED_PRIVILEGE_DRIFT'
               or recovery_status == 'FAIL_DECLARED')
    indeterminate = (acl_status == 'INDETERMINATE_ACL_TRANSLATION'
                     or privilege_status == 'INDETERMINATE_EVIDENCE'
                     or recovery_status == 'NOT_TESTED')
    status = ('BLOCKED' if blocked else 'INDETERMINATE' if indeterminate
              else 'PENDING_HUMAN_AND_LIVE_VERIFICATION')
    actions = []
    if acl_status == 'BLOCKED_POTENTIAL_ACL_LOSS': actions.append('REMEDIATE_ACL_DRIFT')
    if privilege_status == 'BLOCKED_PRIVILEGE_DRIFT': actions.append('REMEDIATE_PRIVILEGE_DRIFT')
    if recovery_status == 'FAIL_DECLARED': actions.append('REMEDIATE_RECOVERY_FAILURE')
    if indeterminate: actions.append('COLLECT_MISSING_VERIFIED_EVIDENCE')
    actions.extend(['RUN_LIVE_NAS_ACCESS_AND_RECOVERY_TESTS','REQUIRE_HUMAN_CUTOVER_APPROVAL'])
    report = {'schema':'odmm.cutover-readiness-gate.v1','migration_id':migration_id,
              'status':status, 'acl_status':acl_status,'privilege_status':privilege_status,
              'recovery_status':recovery_status, 'recovery_evidence_ref':ref,
              'evidence_sha256':{'acl':acl_bundle['sha256'], 'privilege':privilege_bundle['sha256']},
              'actions':actions, 'manual_review_required':True,
              'cutover_authorized':False,'production_qualified':False,
              'limitations':['OFFLINE_UNAUTHENTICATED_EVIDENCE','RECOVERY_STATUS_OPERATOR_DECLARED',
                             'NO_LIVE_NAS_ACCESS_TEST','NO_VENDOR_CERTIFICATION']}
    return {'report':report,'sha256':_hash(report)}

def verify_cutover_readiness(bundle, *args):
    if not isinstance(bundle,dict) or bundle != assess_cutover_readiness(*args):
        raise CutoverGateError('REPORT_MISMATCH')
    return True
