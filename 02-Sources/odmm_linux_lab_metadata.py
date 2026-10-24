"""Read-only POSIX metadata comparison; advisory only, never qualifies NAS ACLs.

Author: Abdelhalim Talbi. Linux local regular files only.
"""
import os
import stat
from pathlib import Path
from odmm_linux_lab_verifier import _safe_parent, VerificationError


def _snapshot(path):
    path = Path(path)
    with _safe_parent(path) as (parent_fd, check_chain):
        check_chain()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path.name, flags, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise VerificationError("NOT_REGULAR_FILE")
            # fd-based reads avoid reopening an attacker-controlled pathname.
            names = sorted(os.listxattr(fd))
            if any(name.startswith("system.posix_acl_") for name in names):
                raise VerificationError("POSIX_ACL_REQUIRES_DEDICATED_QUALIFICATION")
            attrs = {name: os.getxattr(fd, name).hex() for name in names}
            after = os.fstat(fd)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
                      "st_mode", "st_uid", "st_gid")
            if any(getattr(before, field) != getattr(after, field) for field in fields):
                raise VerificationError("METADATA_CHANGED_DURING_INSPECTION")
            leaf = path.lstat()
            if (leaf.st_dev, leaf.st_ino) != (before.st_dev, before.st_ino):
                raise VerificationError("PATH_IDENTITY_CHANGED")
            check_chain()
            return {"uid": after.st_uid, "gid": after.st_gid,
                    "mode": stat.S_IMODE(after.st_mode),
                    "mtime_ns": after.st_mtime_ns, "xattrs_hex": attrs}
        finally:
            os.close(fd)


def inspect_metadata(source, target):
    """Conservative local comparison; mismatch and errors require human review."""
    try:
        left, right = _snapshot(source), _snapshot(target)
        differences = [field for field in left if left[field] != right[field]]
        return {"status": "MANUAL_REVIEW_REQUIRED" if differences else "LOCAL_METADATA_MATCH",
                "differences": differences, "source": left, "target": right,
                "read_only": True, "authorizes_resume": False,
                "nas_acl_qualified": False}
    except (OSError, ValueError) as exc:
        return {"status": "MANUAL_REVIEW_REQUIRED", "reason": type(exc).__name__,
                "read_only": True, "authorizes_resume": False,
                "nas_acl_qualified": False}
