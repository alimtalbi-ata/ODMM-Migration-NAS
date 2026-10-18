"""Conservative ACL identity mapping and ordered diff. Author: Abdelhalim Talbi.

This is an offline evidence comparison, NOT an effective-access evaluator.
"""
from dataclasses import dataclass
import re
from odmm_acl_protocol_v2177 import ProtocolACLEvidence, ProtocolACLError

SID = re.compile(r'S-1-(?:\d+-){1,14}\d+\Z')

@dataclass(frozen=True)
class IdentityMapping:
    source_sid: str
    target_sid: str
    directory: str
    attested: bool = False


def validate_mappings(mappings):
    """Enforce injective, attested SID mappings with explicit AD/LDAP provenance."""
    forward, reverse = {}, {}
    for m in mappings:
        if not isinstance(m, IdentityMapping) or not SID.fullmatch(m.source_sid) or not SID.fullmatch(m.target_sid):
            raise ProtocolACLError('INVALID_IDENTITY_MAPPING')
        if m.directory not in ('AD', 'LDAP') or not m.attested:
            raise ProtocolACLError('UNATTESTED_IDENTITY_MAPPING')
        if m.source_sid in forward or m.target_sid in reverse:
            raise ProtocolACLError('COLLIDING_IDENTITY_MAPPING')
        forward[m.source_sid] = m.target_sid
        reverse[m.target_sid] = m.source_sid
    return forward


def compare_smb_acl_identities(source: ProtocolACLEvidence, target: ProtocolACLEvidence, mappings):
    """Compare ordered ACEs and mapped identities, never authorize cutover."""
    if source.protocol != 'SMB' or target.protocol != 'SMB':
        raise ProtocolACLError('SMB_EVIDENCE_REQUIRED')
    if source.collector != target.collector:
        raise ProtocolACLError('INCOMPARABLE_PROVENANCE')
    mapping = validate_mappings(mappings)
    def decode(ace):
        parts = ace.split('|')
        if len(parts) != 4 or parts[0] not in ('ALLOW', 'DENY') or not SID.fullmatch(parts[1]) or parts[3] not in ('EXPLICIT', 'INHERITED'):
            raise ProtocolACLError('INVALID_ACE')
        return tuple(parts)
    src = [decode(x) for x in source.entries]
    dst = [decode(x) for x in target.entries]
    missing = sorted({ace[1] for ace in src if ace[1] not in mapping})
    translated = [(kind, mapping.get(sid, '<UNMAPPED>'), rights, inheritance) for kind, sid, rights, inheritance in src]
    diffs = [{'index': i, 'source': translated[i] if i < len(translated) else None,
              'target': dst[i] if i < len(dst) else None}
             for i in range(max(len(translated), len(dst)))
             if i >= len(translated) or i >= len(dst) or translated[i] != dst[i]]
    return {'ordered_acl_equal': not diffs and not missing,
            'missing_identity_mappings': missing, 'differences': diffs,
            'source_ace_count': len(src), 'target_ace_count': len(dst),
            'identity_mapping_attested': not missing,
            'effective_access_verified': False, 'nas_cutover_authorized': False}
