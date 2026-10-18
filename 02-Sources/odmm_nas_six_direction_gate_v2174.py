"""Fail-closed qualification evidence gate for six ordered NAS migrations.
Author: Abdelhalim Talbi. Assessment only; no physical NAS certification.
"""
from dataclasses import dataclass
from collections.abc import Mapping
from odmm_nas_pair_matrix_v2128 import plan_pair

TRIAD = ('netapp_ontap', 'pure_flashblade', 'dell_onefs')
REQUIRED = ('source_inventory', 'target_inventory', 'source_acl', 'target_acl',
            'identity_mapping', 'effective_access', 'metadata_fidelity',
            'native_copy', 'delta_consistency', 'rollback', 'distributed_fencing')

@dataclass(frozen=True)
class EvidenceAssessment:
    direction: str
    missing: tuple[str, ...]
    unverified: tuple[str, ...]
    blocked: bool = True
    cutover_authorized: bool = False
    certification: str = 'NOT_CERTIFIED'

def assess(source, target, evidence):
    """Only immutable assessment; evidence cannot override platform qualification."""
    plan = plan_pair(source, target)
    if plan.source not in TRIAD or plan.target not in TRIAD or plan.source == plan.target:
        raise ValueError('OUTSIDE_SIX_DIRECTION_SCOPE')
    if not isinstance(evidence, Mapping):
        raise ValueError('EVIDENCE_MAPPING_REQUIRED')
    missing = tuple(k for k in REQUIRED if k not in evidence)
    # Never treat truthy strings, numeric values, or arbitrary dicts as verified.
    unverified = tuple(k for k in REQUIRED if k in evidence and evidence[k] is not True)
    return EvidenceAssessment(plan.direction, missing, unverified)

def six_direction_report(*, protocol='SMB3'):
    result = []
    for s in TRIAD:
        for t in TRIAD:
            if s != t:
                result.append(assess({'vendor':s,'protocol':protocol,'namespace':'/src','inventory_complete':True},
                                     {'vendor':t,'protocol':protocol,'namespace':'/dst','inventory_complete':True}, {}))
    return tuple(result)
