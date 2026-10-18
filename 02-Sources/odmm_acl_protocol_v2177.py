"""Conservative, read-only protocol ACL evidence adapters. Author: Abdelhalim Talbi.

Parsing a vendor/tool report does NOT establish effective-access equivalence.
"""
from dataclasses import dataclass
import hashlib
import re

class ProtocolACLError(ValueError):
    pass

@dataclass(frozen=True)
class ProtocolACLEvidence:
    protocol: str
    collector: str
    entries: tuple[str, ...]
    sha256: str
    effective_access_verified: bool = False
    cutover_authorized: bool = False

_NFS = re.compile(r'^[ADUL]:[fdinSFI]*:[^:\r\n]+:[rwaDxtTnNcCyos]*$')
_SMB = re.compile(r'^(ALLOW|DENY)\|([^|\r\n]+)\|([A-Z_]+(?:,[A-Z_]+)*)\|(INHERITED|EXPLICIT)$')

def parse_protocol_acl(protocol: str, collector: str, raw: bytes, *, max_bytes: int = 262144, max_entries: int = 4096) -> ProtocolACLEvidence:
    """Accept strict NFSv4 ACE lines or canonical SMB ACE lines.

    SMB canonical input: ALLOW|S-1-...|READ,WRITE|EXPLICIT.
    ACL ordering is preserved (DENY/ALLOW ordering is semantically significant).
    """
    if protocol not in ('NFSv4', 'SMB') or not collector or not isinstance(raw, bytes):
        raise ProtocolACLError('UNSUPPORTED_PROVENANCE')
    if not raw or len(raw) > max_bytes or b'\x00' in raw:
        raise ProtocolACLError('INVALID_ACL_SIZE')
    try:
        lines = raw.decode('utf-8', 'strict').splitlines()
    except UnicodeError as exc:
        raise ProtocolACLError('INVALID_ENCODING') from exc
    if not lines or len(lines) > max_entries or any(not x or x != x.strip() for x in lines):
        raise ProtocolACLError('INVALID_ENTRIES')
    if protocol == 'NFSv4':
        if not all(_NFS.fullmatch(line) for line in lines):
            raise ProtocolACLError('INVALID_NFSV4_ACE')
    else:
        if not all(_SMB.fullmatch(line) and _SMB.fullmatch(line).group(2).startswith('S-1-') for line in lines):
            raise ProtocolACLError('INVALID_SMB_ACE')
    return ProtocolACLEvidence(protocol, collector, tuple(lines), hashlib.sha256(raw).hexdigest())

def compare_protocol_acl(source: ProtocolACLEvidence, target: ProtocolACLEvidence) -> dict:
    if source.protocol != target.protocol or source.collector != target.collector:
        raise ProtocolACLError('INCOMPARABLE_PROVENANCE')
    return {'ordered_entries_equal': source.entries == target.entries,
            'evidence_hash_equal': source.sha256 == target.sha256,
            'effective_access_verified': False, 'nas_cutover_authorized': False,
            'identity_mapping_verified': False}
