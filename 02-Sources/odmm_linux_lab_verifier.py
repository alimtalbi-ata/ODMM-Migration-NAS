"""Independent local POSIX laboratory verification (read-only, no NAS writes).

Author: Abdelhalim Talbi. Pin immediate parent directories and regular-file
inodes while hashing. No remote NAS fencing or ACL/ownership certification.
"""
import hashlib
import os
import stat
from pathlib import Path

class VerificationError(ValueError):
    pass


def _digest(path, chunk_size=1024 * 1024):
    path = Path(path)
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    leaf_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    pfd = os.open(path.parent, parent_flags)
    try:
        parent_before = os.fstat(pfd)
        if not stat.S_ISDIR(parent_before.st_mode):
            raise VerificationError("PARENT_NOT_DIRECTORY")
        # A parent pathname swap must not redirect the open to a different tree.
        parent_path_before = path.parent.lstat()
        if (parent_path_before.st_dev, parent_path_before.st_ino) != (parent_before.st_dev, parent_before.st_ino):
            raise VerificationError("PARENT_IDENTITY_CHANGED")
        fd = os.open(path.name, leaf_flags, dir_fd=pfd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise VerificationError("NOT_REGULAR_FILE")
            digest = hashlib.sha256()
            with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
                while True:
                    data = stream.read(chunk_size)
                    if not data:
                        break
                    digest.update(data)
            after = os.fstat(fd)
            # Also catch metadata-only changes such as chmod during inspection.
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
            if any(getattr(before, field) != getattr(after, field) for field in fields):
                raise VerificationError("FILE_CHANGED_DURING_VERIFICATION")
            try:
                parent_path_after = path.parent.lstat()
                leaf_path_after = path.lstat()
            except OSError as exc:
                raise VerificationError("PATH_IDENTITY_CHANGED") from exc
            if (not stat.S_ISDIR(parent_path_after.st_mode) or
                    (parent_path_after.st_dev, parent_path_after.st_ino) !=
                    (parent_before.st_dev, parent_before.st_ino) or
                    not stat.S_ISREG(leaf_path_after.st_mode) or
                    (leaf_path_after.st_dev, leaf_path_after.st_ino) !=
                    (before.st_dev, before.st_ino)):
                raise VerificationError("PATH_IDENTITY_CHANGED")
            return {"sha256": digest.hexdigest(), "size": after.st_size,
                    "mode": stat.S_IMODE(after.st_mode)}
        finally:
            os.close(fd)
    finally:
        os.close(pfd)


def verify_pair(source, target):
    source, target = Path(source), Path(target)
    for path in (source, target):
        if path.is_symlink():
            raise VerificationError("SYMLINK_REFUSED")
    try:
        left, right = _digest(source), _digest(target)
    except (OSError, PermissionError) as exc:
        raise VerificationError("FILE_READ_FAILURE") from exc
    if left["size"] != right["size"] or left["sha256"] != right["sha256"]:
        raise VerificationError("CONTENT_MISMATCH")
    if left["mode"] != right["mode"]:
        raise VerificationError("POSIX_MODE_MISMATCH")
    return {"verified": True, "algorithm": "sha256", "source": left,
            "target": right, "nas_acl_qualified": False,
            "note": "Local regular-file content and mode only; no SMB ACL, xattr, ADS or ownership proof"}
