"""V212.6 POSIX metadata evidence and fail-closed verification; author Abdelhalim Talbi.

Local single-file pilot only. No NFSv4/SMB ACL fidelity or distributed fencing claim.
"""
import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass
from odmm_native_secure_v2120 import Blocked, FLAGS, _parts, _parent, _identity
from odmm_native_metadata_gate_v2125 import MetadataGatedStaging

@dataclass(frozen=True)
class FileProof:
    path: str
    sha256: str
    size: int
    mode: int
    uid: int
    gid: int
    xattrs: tuple
    identity: tuple


def _snapshot(rootfd, name):
    parts = _parts(name)
    parent = _parent(rootfd, parts)
    try:
        fd = os.open(parts[-1], FLAGS | getattr(os, 'O_NONBLOCK', 0), dir_fd=parent)
        try:
            first = os.fstat(fd)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
                raise Blocked('UNSAFE_FILE_TYPE')
            if not hasattr(os, 'listxattr'):
                raise Blocked('XATTR_INSPECTION_UNAVAILABLE')
            try:
                xattrs = tuple(sorted(os.listxattr(fd)))
            except (OSError, TypeError) as exc:
                raise Blocked('XATTR_INSPECTION_FAILED') from exc
            if xattrs:
                raise Blocked('UNSUPPORTED_XATTR_OR_ACL')
            h = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk: break
                h.update(chunk)
            if _identity(first) != _identity(os.fstat(fd)):
                raise Blocked('FILE_CHANGED_DURING_PROOF')
            return FileProof(name, h.hexdigest(), first.st_size, stat.S_IMODE(first.st_mode), first.st_uid, first.st_gid, xattrs, _identity(first))
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _seal(payload):
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return hashlib.sha256(raw).hexdigest()

class EvidenceGatedStaging:
    def __init__(self, gated: MetadataGatedStaging):
        if not isinstance(gated, MetadataGatedStaging):
            raise Blocked('INVALID_EVIDENCE_GATE')
        self.gated = gated

    def stage(self, name):
        owned = self.gated.owned
        if not owned._fence():
            raise Blocked('STALE_OWNER')
        src_before = _snapshot(owned.staging.srcfd, name)
        if src_before.mode != 0o600 or src_before.uid != os.geteuid() or src_before.gid != os.getegid():
            raise Blocked('UNSUPPORTED_SOURCE_METADATA')
        result = self.gated.stage(name)
        if not owned._fence():
            raise Blocked('STALE_OWNER_AFTER_PUBLICATION_REVIEW_REQUIRED')
        src_after = _snapshot(owned.staging.srcfd, name)
        dst_after = _snapshot(owned.staging.dstfd, name)
        if src_before != src_after:
            raise Blocked('SOURCE_CHANGED_AFTER_PUBLICATION_REVIEW_REQUIRED')
        # Identity is deliberately excluded from cross-filesystem equality.
        attrs = ('sha256', 'size', 'mode', 'uid', 'gid', 'xattrs')
        if any(getattr(src_before, k) != getattr(dst_after, k) for k in attrs):
            raise Blocked('TARGET_METADATA_MISMATCH_REVIEW_REQUIRED')
        if result['transfer'].sha256 != dst_after.sha256:
            raise Blocked('JOURNAL_DIGEST_MISMATCH_REVIEW_REQUIRED')
        evidence = {
            'schema': 'odmm.native.metadata-evidence.v2126',
            'source': asdict(src_before), 'target': asdict(dst_after),
            'ownership': {'resource': owned.claim.resource, 'epoch': owned.claim.epoch},
            'metadata_scope': 'POSIX_0600_UID_GID_NO_XATTR_ONLY',
            'engine': 'ODMM_NATIVE', 'local_posix_verified': True,
            'acl_fidelity_verified': False, 'distributed_fencing_verified': False,
            'cutover_authorized': False, 'requires_human_review': True,
        }
        evidence['sha256'] = _seal(evidence)
        return evidence


def verify_evidence_seal(evidence):
    if not isinstance(evidence, dict) or 'sha256' not in evidence:
        return False
    body = {k: v for k, v in evidence.items() if k != 'sha256'}
    return _seal(body) == evidence['sha256']
