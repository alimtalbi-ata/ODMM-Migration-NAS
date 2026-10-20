"""Independent local POSIX laboratory verification (read-only, no NAS writes).

Author: Abdelhalim Talbi. Reject symlinks and non-regular files; stream hashes.
"""
import hashlib
import os
import stat
from pathlib import Path

class VerificationError(ValueError):
    pass

def _digest(path, chunk_size=1024 * 1024):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
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
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise VerificationError("FILE_CHANGED_DURING_VERIFICATION")
        return {"sha256": digest.hexdigest(), "size": after.st_size,
                "mode": stat.S_IMODE(after.st_mode)}
    finally:
        os.close(fd)

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
