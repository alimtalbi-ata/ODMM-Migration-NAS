"""Conservative NAS identity/ACL preflight. No access to vendor NAS is claimed.
Author: Abdelhalim Talbi.
"""
from dataclasses import dataclass
from collections.abc import Mapping
from odmm_nas_six_direction_gate_v2174 import assess

@dataclass(frozen=True)
class IdentityPreflight:
    direction: str
    blockers: tuple[str, ...]
    cutover_authorized: bool = False
    acl_fidelity_verified: bool = False
    engine: str = 'ODMM_NATIVE'


def preflight(source, target, *, identities, acl_samples, evidence=None):
    """Check explicit AD/LDAP SID and POSIX UID/GID mappings and ACL samples.

    This is a structural preflight, not proof of effective rights or NAS support.
    """
    assessment = assess(source, target, {} if evidence is None else evidence)
    blockers = []
    if not isinstance(identities, (tuple, list)) or not identities:
        blockers.append('IDENTITY_MAPPINGS_MISSING')
    else:
        seen_source, seen_target = set(), set()
        for row in identities:
            if not isinstance(row, Mapping):
                blockers.append('IDENTITY_ROW_INVALID'); continue
            kind, src, dst = row.get('kind'), row.get('source'), row.get('target')
            if kind not in ('UID','GID','SID','AD','LDAP') or not isinstance(src, str) or not src.strip() or not isinstance(dst, str) or not dst.strip():
                blockers.append('IDENTITY_ROW_INVALID'); continue
            pair_src, pair_dst = (kind, src), (kind, dst)
            if pair_src in seen_source or pair_dst in seen_target:
                blockers.append('IDENTITY_MAPPING_COLLISION')
            seen_source.add(pair_src); seen_target.add(pair_dst)
    if not isinstance(acl_samples, (tuple, list)) or not acl_samples:
        blockers.append('ACL_SAMPLES_MISSING')
    else:
        seen = set()
        for row in acl_samples:
            if not isinstance(row, Mapping) or not isinstance(row.get('path'), str) or not row['path'].startswith('/') or row['path'] in seen:
                blockers.append('ACL_SAMPLE_INVALID'); continue
            seen.add(row['path'])
            if row.get('source_acl') is None or row.get('target_acl') is None:
                blockers.append('ACL_SAMPLE_INCOMPLETE')
            if row.get('effective_access_verified') is not True:
                blockers.append('EFFECTIVE_ACCESS_UNVERIFIED')
            if row.get('acl_equivalent') is not True:
                blockers.append('ACL_EQUIVALENCE_UNVERIFIED')
    blockers.extend('EVIDENCE_MISSING_'+x.upper() for x in assessment.missing)
    blockers.extend('EVIDENCE_UNVERIFIED_'+x.upper() for x in assessment.unverified)
    blockers.append('VENDOR_NAS_NOT_PHYSICALLY_QUALIFIED')
    return IdentityPreflight(assessment.direction, tuple(sorted(set(blockers))))
