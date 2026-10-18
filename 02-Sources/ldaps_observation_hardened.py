"""V188.8: fail-closed bounded file observations resistant to symlink and in-place races.

Read-only evidence only; no recovery, cutover, or publication permissions.
"""
import hashlib
import os
import stat
import time
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError

MAX_BYTES = 1024 * 1024

def observe_file(path, *, max_bytes=MAX_BYTES, read_hook=None):
    """Open a regular file without following final symlink; detect in-place mutations.

    Not a snapshot guarantee against a malicious concurrent writer that restores all
    metadata; immutable/snapshot-backed evidence requires external enforcement.
    """
    p = Path(path)
    if not p.is_absolute() or not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 0 < max_bytes <= MAX_BYTES:
        raise IdentityPinError('OBSERVATION_FILE_INVALID')
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    try:
        fd = os.open(p, flags)
    except OSError as exc:
        raise IdentityPinError('OBSERVATION_FILE_OPEN_REFUSED') from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise IdentityPinError('OBSERVATION_FILE_UNSAFE')
        if read_hook is not None:
            read_hook()
        data = bytearray()
        while len(data) <= max_bytes:
            block = os.read(fd, min(65536, max_bytes + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if len(data) > max_bytes or len(data) != before.st_size or identity(before) != identity(after):
            raise IdentityPinError('OBSERVATION_FILE_CHANGED')
        return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
                'device': before.st_dev, 'inode': before.st_ino, 'observed_at_ns': time.time_ns(),
                'manual_review_required': True, 'cutover_authorized': False,
                'recovery_authorized': False, 'publication_authorized': False}
    except OSError as exc:
        raise IdentityPinError('OBSERVATION_FILE_READ_REFUSED') from exc
    finally:
        os.close(fd)
