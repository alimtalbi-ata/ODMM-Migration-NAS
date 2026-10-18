"""Read-only local identity-bound access evidence, never a NAS cutover gate.
Author: Abdelhalim Talbi.
"""
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from readonly_access_probe import probe_readonly, AccessProbeError

class LiveAccessError(ValueError):
    pass

@dataclass(frozen=True)
class AccessCase:
    case_id: str
    source_root: str
    target_root: str
    relative_path: str
    expected_euid: int
    expected_egid: int
    source_vendor: str
    target_vendor: str

VENDORS = frozenset({'NetApp', 'FlashBlade', 'OneFS'})

def _validate(case):
    if not isinstance(case, AccessCase):
        raise LiveAccessError('INVALID_CASE')
    if not isinstance(case.case_id, str) or not case.case_id or len(case.case_id)>128:
        raise LiveAccessError('INVALID_CASE_ID')
    if case.source_vendor not in VENDORS or case.target_vendor not in VENDORS or case.source_vendor==case.target_vendor:
        raise LiveAccessError('UNSUPPORTED_VENDOR_DIRECTION')
    if any(not isinstance(x,str) or not x for x in (case.source_root,case.target_root,case.relative_path)):
        raise LiveAccessError('INVALID_PATH')
    if not all(isinstance(x,int) and not isinstance(x,bool) and x>=0 for x in (case.expected_euid,case.expected_egid)):
        raise LiveAccessError('INVALID_IDENTITY')
    if os.geteuid()!=case.expected_euid or os.getegid()!=case.expected_egid:
        raise LiveAccessError('EXECUTION_IDENTITY_MISMATCH')

def run_readonly_case(case):
    """Observe two local mounted paths using current OS identity; never impersonate.

    Outcomes reflect open(O_RDONLY) only, not actual SMB/NFS rights equivalence.
    """
    _validate(case)
    try:
        source=probe_readonly(case.source_root,case.relative_path,expected_euid=case.expected_euid,expected_egid=case.expected_egid)
        target=probe_readonly(case.target_root,case.relative_path,expected_euid=case.expected_euid,expected_egid=case.expected_egid)
    except (AccessProbeError,OSError) as exc:
        raise LiveAccessError('PROBE_FAILED_CLOSED') from exc
    equal=source['report']['outcome']==target['report']['outcome']
    report={'schema':'odmm.access-pair.v2182','case_id':case.case_id,
            'direction':f'{case.source_vendor}->{case.target_vendor}',
            'relative_path':case.relative_path,
            'execution_euid':case.expected_euid,'execution_egid':case.expected_egid,
            'source_outcome':source['report']['outcome'],'target_outcome':target['report']['outcome'],
            'source_evidence_sha256':source['sha256'],'target_evidence_sha256':target['sha256'],
            'local_open_outcomes_equal':equal,'identity_impersonation':False,
            'effective_nas_acl_verified':False,'ad_ldap_authentication_verified':False,
            'cutover_authorized':False,'write_performed':False,
            'limitations':['LOCAL_MOUNT_OBSERVATION_ONLY','CURRENT_PROCESS_IDENTITY_ONLY',
                           'NO_AD_LDAP_GROUP_RESOLUTION','NO_SMB_SHARE_ACL_EVALUATION',
                           'NO_REMOTE_NAS_ATTESTATION']}
    digest=hashlib.sha256(json.dumps(report,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    return {'report':report,'sha256':digest}

def compare_cases(cases):
    """Aggregate six-direction local evidence without promoting qualification."""
    cases=list(cases)
    if not cases or len({c.case_id for c in cases})!=len(cases):
        raise LiveAccessError('EMPTY_OR_DUPLICATE_CASES')
    results=[run_readonly_case(c) for c in cases]
    return {'schema':'odmm.access-campaign.v2182','cases':results,
            'all_local_outcomes_equal':all(x['report']['local_open_outcomes_equal'] for x in results),
            'nas_qualified':False,'cutover_authorized':False}
