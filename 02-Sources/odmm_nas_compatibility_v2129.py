"""Conservative, read-only NAS compatibility qualification. Author: Abdelhalim Talbi.

Capabilities are provided evidence, not manufacturer-certified facts.
"""
from dataclasses import dataclass, asdict
from collections.abc import Mapping
from odmm_nas_pair_matrix_v2128 import normalize_vendor, PROTOCOLS, matrix, plan_pair

@dataclass(frozen=True)
class Compatibility:
    source: str
    target: str
    classification: str
    blockers: tuple[str, ...]
    common_protocols: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    engine: str = 'ODMM_NATIVE'
    cutover_authorized: bool = False
    certified: bool = False


def _endpoint(value, role):
    if not isinstance(value, Mapping):
        raise ValueError(role+'_MAPPING_REQUIRED')
    vendor = normalize_vendor(value.get('vendor'))
    protocols = value.get('protocols')
    if not isinstance(protocols, (list,tuple,set,frozenset)) or not protocols or any(not isinstance(p,str) or p not in PROTOCOLS for p in protocols):
        raise ValueError(role+'_PROTOCOLS_INVALID')
    evidence = value.get('evidence')
    if not isinstance(evidence, Mapping):
        raise ValueError(role+'_EVIDENCE_REQUIRED')
    evidence_id = evidence.get('id')
    if not isinstance(evidence_id,str) or not evidence_id.strip() or len(evidence_id)>256:
        raise ValueError(role+'_EVIDENCE_ID_REQUIRED')
    return vendor, frozenset(protocols), evidence_id.strip(), evidence.get('verified') is True, value.get('nas_capable')


def qualify_pair(source, target, *, identity_mapping_verified=False, acl_verified=False,
                 effective_access_verified=False, metadata_verified=False,
                 native_engine_verified=False, rollback_verified=False,
                 distributed_fencing_verified=False):
    """Never authorizes cutover; verified flags are externally supplied, not independently checked."""
    sv, sp, se, sev, snas = _endpoint(source,'SOURCE')
    tv, tp, te, tev, tnas = _endpoint(target,'TARGET')
    common = tuple(sorted(sp & tp))
    blockers = []
    if not sev: blockers.append('SOURCE_CAPABILITY_EVIDENCE_UNVERIFIED')
    if not tev: blockers.append('TARGET_CAPABILITY_EVIDENCE_UNVERIFIED')
    if snas is not True: blockers.append('SOURCE_NAS_CAPABILITY_NOT_VERIFIED' if snas is not False else 'SOURCE_NAS_UNSUPPORTED_DECLARED')
    if tnas is not True: blockers.append('TARGET_NAS_CAPABILITY_NOT_VERIFIED' if tnas is not False else 'TARGET_NAS_UNSUPPORTED_DECLARED')
    if not common: blockers.append('NO_COMMON_PROTOCOL')
    checks = {'IDENTITY_MAPPING_NOT_VERIFIED':identity_mapping_verified,
              'ACL_NOT_VERIFIED':acl_verified,
              'EFFECTIVE_ACCESS_NOT_VERIFIED':effective_access_verified,
              'METADATA_NOT_VERIFIED':metadata_verified,
              'NATIVE_ENGINE_NOT_VERIFIED':native_engine_verified,
              'ROLLBACK_NOT_VERIFIED':rollback_verified,
              'DISTRIBUTED_FENCING_NOT_VERIFIED':distributed_fencing_verified}
    blockers += [key for key,ok in checks.items() if ok is not True]
    blockers.append('NO_INDEPENDENT_VENDOR_FIRMWARE_CERTIFICATION')
    blockers.append('CUTOVER_NOT_AUTHORIZED')
    if (snas is False and sev) or (tnas is False and tev):
        status='NOT_APPLICABLE'
    elif sev and tev and snas is True and tnas is True and common:
        status='CONDITIONAL'
    else:
        status='NOT_QUALIFIED'
    return Compatibility(sv,tv,status,tuple(sorted(set(blockers))),common,(se,te))


def compatibility_matrix(*, protocol='SMB3'):
    """All candidate directions; no invented firmware or hardware support assertions."""
    return {'directions':len(matrix(protocol=protocol)), 'vendor_count':15,
            'classification':'NOT_QUALIFIED', 'supported':0,
            'cutover_authorized':False,
            'note':'No vendor-specific firmware capability inventory was supplied.'}
