"""Conservative offline SMB ACE permission projection, not a live AD/LDAP access check.
Author: Abdelhalim Talbi.
"""
from dataclasses import dataclass
from odmm_acl_identity_v2180 import validate_mappings, SID
from odmm_acl_protocol_v2177 import ProtocolACLError, ProtocolACLEvidence

RIGHTS = frozenset({'READ', 'WRITE', 'EXECUTE', 'DELETE'})

@dataclass(frozen=True)
class PrincipalEvidence:
    user_sid: str
    group_sids: tuple[str, ...]
    directory: str
    attested: bool = False


def _principal(p):
    if not isinstance(p, PrincipalEvidence) or not p.attested or p.directory not in ('AD', 'LDAP'):
        raise ProtocolACLError('UNATTESTED_MEMBERSHIP')
    sids = (p.user_sid,) + p.group_sids
    if any(not isinstance(s, str) or not SID.fullmatch(s) for s in sids) or len(set(sids)) != len(sids):
        raise ProtocolACLError('INVALID_MEMBERSHIP')
    return set(sids)


def project_rights(acl: ProtocolACLEvidence, principal: PrincipalEvidence):
    """Ordered first-applicable ACE projection for a restricted canonical ACL subset.

    This is NOT Windows token evaluation (no nested groups, owner rights, share ACL,
    generic-right expansion, object ACE, conditional ACE or live identity lookup).
    """
    if not isinstance(acl, ProtocolACLEvidence) or acl.protocol != 'SMB':
        raise ProtocolACLError('SMB_EVIDENCE_REQUIRED')
    subjects = _principal(principal)
    decided = {}
    for line in acl.entries:
        parts = line.split('|')
        if len(parts) != 4 or parts[0] not in ('ALLOW', 'DENY') or parts[3] not in ('EXPLICIT', 'INHERITED') or not SID.fullmatch(parts[1]):
            raise ProtocolACLError('INVALID_ACE')
        tokens = parts[2].split(',')
        if len(tokens) != len(set(tokens)) or not tokens or not set(tokens) <= RIGHTS:
            raise ProtocolACLError('UNSUPPORTED_RIGHTS')
        if parts[1] in subjects:
            for right in tokens:
                decided.setdefault(right, parts[0] == 'ALLOW')
    return {right: decided.get(right, False) for right in sorted(RIGHTS)}


def compare_principal_rights(source, target, source_principal, target_principal, mappings):
    """Offline comparison; always refuse production authorization."""
    mapping = validate_mappings(mappings)
    src_subjects = _principal(source_principal)
    dst_subjects = _principal(target_principal)
    if source.collector != target.collector or source.protocol != 'SMB' or target.protocol != 'SMB':
        raise ProtocolACLError('INCOMPARABLE_PROVENANCE')
    if source_principal.directory != target_principal.directory:
        raise ProtocolACLError('DIRECTORY_MISMATCH')
    if any(s not in mapping for s in src_subjects) or {mapping[s] for s in src_subjects} != dst_subjects or mapping[source_principal.user_sid] != target_principal.user_sid:
        raise ProtocolACLError('MEMBERSHIP_MAPPING_MISMATCH')
    a = project_rights(source, source_principal)
    b = project_rights(target, target_principal)
    return {'offline_projection_equal': a == b, 'source_rights': a, 'target_rights': b,
            'differences': sorted(k for k in RIGHTS if a[k] != b[k]),
            'effective_access_verified': False, 'nas_cutover_authorized': False,
            'requires_live_ad_ldap_access_tests': True}
