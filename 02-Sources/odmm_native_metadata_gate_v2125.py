"""Conservative source metadata gate, POSIX local pilot. Author: Abdelhalim Talbi.

Never asserts ACL equivalence; rejects all xattrs and nontrivial POSIX permissions.
"""
import os
import stat
from dataclasses import dataclass
from odmm_native_secure_v2120 import Blocked, FLAGS, _parts, _parent, _identity
from odmm_native_owned_stage_v2123 import OwnedStaging

@dataclass(frozen=True)
class MetadataEvidence:
    path: str
    source_identity: tuple
    mode: int
    uid: int
    gid: int
    xattrs: tuple
    acl_fidelity_verified: bool = False
    cutover_authorized: bool = False

class MetadataGatedStaging:
    """Fail closed on any source metadata not representable by the local pilot.

    The pilot publishes target mode 0600; it does NOT preserve owner, ACL or xattrs.
    It is restricted to same effective UID/GID and source mode 0600. Not a NAS engine.
    """
    def __init__(self, owned: OwnedStaging):
        if not isinstance(owned, OwnedStaging):
            raise Blocked('INVALID_METADATA_GATE')
        self.owned = owned

    def inspect(self, name):
        parts = _parts(name)
        if not self.owned._fence():
            raise Blocked('STALE_OWNER')
        staging = self.owned.staging
        parent = _parent(staging.srcfd, parts)
        try:
            fd = os.open(parts[-1], FLAGS | getattr(os, 'O_NONBLOCK', 0), dir_fd=parent)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise Blocked('UNSAFE_SOURCE_TYPE')
                if stat.S_IMODE(before.st_mode) != 0o600:
                    raise Blocked('UNSUPPORTED_MODE')
                if before.st_uid != os.geteuid() or before.st_gid != os.getegid():
                    raise Blocked('UNSUPPORTED_OWNER')
                if not hasattr(os, 'listxattr'):
                    raise Blocked('XATTR_INSPECTION_UNAVAILABLE')
                try:
                    attributes = tuple(sorted(os.listxattr(fd)))
                except (OSError, TypeError) as exc:
                    raise Blocked('XATTR_INSPECTION_FAILED') from exc
                if attributes:
                    raise Blocked('UNSUPPORTED_XATTR_OR_ACL')
                if _identity(before) != _identity(os.fstat(fd)):
                    raise Blocked('SOURCE_CHANGED')
                return MetadataEvidence(name, _identity(before), stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid, attributes)
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    def stage(self, name):
        before = self.inspect(name)
        # A concurrent metadata mutation is still possible between checks. No production claim.
        result = self.owned.stage(name)
        after = self.inspect(name)
        if before != after:
            raise Blocked('SOURCE_METADATA_CHANGED_AFTER_PUBLICATION_REVIEW_REQUIRED')
        return {'transfer': result, 'metadata': after, 'cutover_authorized': False,
                'acl_fidelity_verified': False, 'requires_human_review': True}
