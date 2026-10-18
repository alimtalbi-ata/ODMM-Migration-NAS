"""Bidirectional NetApp ONTAP <-> Pure FlashBlade migration qualification.
Read-only, conservative planning. Author: Abdelhalim Talbi.
No claim of vendor API integration, ACL translation or cutover readiness.
"""
from dataclasses import dataclass
from typing import Mapping

SUPPORTED={'NFS3','NFS4','SMB3'}
VENDORS={'netapp':'NetApp ONTAP','flashblade':'Pure FlashBlade'}

@dataclass(frozen=True)
class PairAssessment:
    schema: str
    direction: str
    status: str
    blockers: tuple
    warnings: tuple
    phases: tuple
    cutover_authorized: bool = False
    engine: str = 'ODMM_NATIVE'

def assess_pair(source: Mapping, target: Mapping, proofs: Mapping | None = None) -> PairAssessment:
    """Assess supplied, independently verified facts; missing facts block.

    Endpoint fields: vendor, protocol, namespace, capacity_free_bytes,
    required_bytes, identity_domain, acl_model, features (iterable).
    Proofs are booleans from trusted collectors, not user-asserted cutover approval.
    """
    proofs=proofs or {}
    blockers=[]; warnings=[]
    if not isinstance(source, Mapping) or not isinstance(target, Mapping):
        raise ValueError('ENDPOINTS_REQUIRED')
    sv=source.get('vendor'); tv=target.get('vendor')
    direction=f'{sv or "unknown"}_TO_{tv or "unknown"}'
    if (sv,tv) not in {('netapp','flashblade'),('flashblade','netapp')}:
        blockers.append('UNSUPPORTED_VENDOR_DIRECTION')
    for side, ep in (('SOURCE',source),('TARGET',target)):
        if not isinstance(ep.get('namespace'),str) or not ep.get('namespace'):
            blockers.append(side+'_NAMESPACE_UNVERIFIED')
        if ep.get('protocol') not in SUPPORTED:
            blockers.append(side+'_PROTOCOL_UNVERIFIED')
        if not ep.get('identity_domain'):
            blockers.append(side+'_IDENTITY_UNVERIFIED')
        if ep.get('acl_model') not in {'NTFS','NFS4','POSIX'}:
            blockers.append(side+'_ACL_MODEL_UNVERIFIED')
    if source.get('protocol')!=target.get('protocol'):
        blockers.append('CROSS_PROTOCOL_TRANSLATION_UNQUALIFIED')
    if source.get('acl_model')!=target.get('acl_model'):
        blockers.append('ACL_TRANSLATION_UNQUALIFIED')
    if source.get('identity_domain')!=target.get('identity_domain'):
        blockers.append('IDENTITY_MAPPING_REQUIRED')
    try:
        required=source['required_bytes']; free=target['capacity_free_bytes']
        if type(required) is not int or type(free) is not int or required<=0 or free<0:
            raise ValueError()
        if free < required:
            blockers.append('TARGET_CAPACITY_INSUFFICIENT')
    except (KeyError,ValueError,TypeError):
        blockers.append('CAPACITY_EVIDENCE_UNVERIFIED')
    sf=set(source.get('features') or []); tf=set(target.get('features') or [])
    for feature in sorted(sf-tf):
        if feature in {'snapshots','quotas','junctions','qtrees','hardlinks','symlinks','xattrs','ads','smb_sacl','nfs4_acl'}:
            blockers.append('FEATURE_TRANSLATION_REQUIRED_'+feature.upper())
        else:
            warnings.append('SOURCE_FEATURE_UNASSESSED_'+str(feature).upper())
    mandatory=('source_inventory','target_inventory','acl_sample_verified','effective_access_verified',
               'identity_mapping_verified','delta_sync_verified','rollback_tested',
               'fencing_verified','checksum_verified','protocol_semantics_verified')
    for key in mandatory:
        if proofs.get(key) is not True:
            blockers.append('PROOF_REQUIRED_'+key.upper())
    phases=('DISCOVER_BOTH_ENDPOINTS','COMPARE_PROTOCOL_IDENTITY_ACL',
            'CAPACITY_AND_NAMESPACE_MAPPING','NATIVE_INITIAL_COPY','NATIVE_INCREMENTAL_DELTA',
            'METADATA_AND_EFFECTIVE_ACCESS_VERIFY','FENCED_CUTOVER_HITL','POST_CUTOVER_VERIFY','ROLLBACK_WINDOW')
    return PairAssessment('odmm.netapp.flashblade.v2112',direction,'BLOCKED',
                          tuple(sorted(set(blockers))),tuple(sorted(set(warnings))),phases)
