"""Identity-scoped ACL regression report for ODMM campaigns.

Consumes already collected, locally observed evidence. It does not claim live
AD/LDAP or NAS effective-rights verification and never authorizes cutover.
Author: Abdelhalim Talbi.
"""
from __future__ import annotations
import hashlib
import json
from collections import defaultdict

class IdentityReportError(ValueError):
    pass

VENDORS = frozenset({'NetApp', 'FlashBlade', 'OneFS'})
REQUIRED = {
    'case_id', 'direction', 'relative_path', 'execution_euid', 'execution_egid',
    'source_outcome', 'target_outcome', 'source_evidence_sha256',
    'target_evidence_sha256', 'local_open_outcomes_equal', 'cutover_authorized',
    'effective_nas_acl_verified', 'ad_ldap_authentication_verified'
}

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def _sha(s):
    return isinstance(s, str) and len(s) == 64 and all(c in '0123456789abcdef' for c in s)

def build_identity_regression_report(records):
    """Build a deterministic report from worker records (each has report + sha256).

    Optional identity labels may be supplied as `identity_ref` and `group_refs`
    alongside the worker report; they are opaque operator-provided labels, not
    proof of directory membership. No raw credentials are accepted or emitted.
    """
    records = list(records)
    if not records or len(records) > 100:
        raise IdentityReportError('INVALID_RECORD_COUNT')
    seen = set()
    grouped = defaultdict(list)
    normalized = []
    for item in records:
        if not isinstance(item, dict) or not isinstance(item.get('report'), dict):
            raise IdentityReportError('INVALID_EVIDENCE_RECORD')
        report = item['report']
        if not REQUIRED.issubset(report):
            raise IdentityReportError('INCOMPLETE_EVIDENCE')
        digest = item.get('sha256')
        if not _sha(digest) or hashlib.sha256(_canonical(report)).hexdigest() != digest:
            raise IdentityReportError('EVIDENCE_DIGEST_MISMATCH')
        case_id = report['case_id']
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            raise IdentityReportError('DUPLICATE_OR_INVALID_CASE')
        seen.add(case_id)
        direction = report['direction']
        parts = direction.split('->') if isinstance(direction, str) else []
        if len(parts) != 2 or parts[0] not in VENDORS or parts[1] not in VENDORS or parts[0] == parts[1]:
            raise IdentityReportError('INVALID_DIRECTION')
        if report['cutover_authorized'] is not False or report['effective_nas_acl_verified'] is not False or report['ad_ldap_authentication_verified'] is not False:
            raise IdentityReportError('UNSUPPORTED_QUALIFICATION_CLAIM')
        if type(report['local_open_outcomes_equal']) is not bool:
            raise IdentityReportError('INVALID_COMPARISON_RESULT')
        identity_ref = item.get('identity_ref', 'UNSPECIFIED_LOCAL_IDENTITY')
        group_refs = item.get('group_refs', [])
        if not isinstance(identity_ref, str) or not identity_ref or len(identity_ref) > 256:
            raise IdentityReportError('INVALID_IDENTITY_REF')
        if not isinstance(group_refs, list) or any(not isinstance(g, str) or not g or len(g) > 256 for g in group_refs) or len(group_refs) != len(set(group_refs)):
            raise IdentityReportError('INVALID_GROUP_REFS')
        clean = {'case_id': case_id, 'direction': direction,
                 'relative_path': report['relative_path'], 'identity_ref': identity_ref,
                 'group_refs': sorted(group_refs),
                 'source_outcome': report['source_outcome'], 'target_outcome': report['target_outcome'],
                 'local_open_outcomes_equal': report['local_open_outcomes_equal'],
                 'source_evidence_sha256': report['source_evidence_sha256'],
                 'target_evidence_sha256': report['target_evidence_sha256'], 'worker_evidence_sha256': digest}
        normalized.append(clean)
        grouped[identity_ref].append(clean)
    identity_summaries = []
    for identity in sorted(grouped):
        rows = grouped[identity]
        identity_summaries.append({
            'identity_ref': identity,
            'case_count': len(rows),
            'group_refs': sorted({g for r in rows for g in r['group_refs']}),
            'directions': sorted({r['direction'] for r in rows}),
            'local_outcome_mismatch_count': sum(not r['local_open_outcomes_equal'] for r in rows),
            'mismatches': [{'case_id': r['case_id'], 'direction': r['direction'],
                            'source_outcome': r['source_outcome'], 'target_outcome': r['target_outcome']}
                           for r in rows if not r['local_open_outcomes_equal']]
        })
    normalized.sort(key=lambda r: (r['identity_ref'], r['direction'], r['case_id']))
    payload = {'schema': 'odmm.identity-regression-report.v2188', 'cases': normalized,
               'identity_summaries': identity_summaries,
               'case_count': len(normalized),
               'local_outcome_mismatch_count': sum(not r['local_open_outcomes_equal'] for r in normalized),
               'identity_count': len(identity_summaries),
               'directory_membership_attested': False, 'effective_nas_acl_verified': False,
               'ad_ldap_authentication_verified': False, 'nas_qualified': False,
               'cutover_authorized': False,
               'limitations': ['LOCAL_MOUNT_OBSERVATION_ONLY', 'IDENTITY_AND_GROUP_LABELS_NOT_DIRECTORY_PROOF',
                               'NO_LIVE_AD_LDAP_MEMBERSHIP_RESOLUTION', 'NO_REMOTE_NAS_ACL_EVALUATION']}
    return {'report': payload, 'sha256': hashlib.sha256(_canonical(payload)).hexdigest()}
