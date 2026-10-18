"""Linux POSIX descriptor-anchored path preflight; no shell and no writes.
This is NOT a race-free guarantee for later pathname-based ACL utilities.
"""
import os
from pathlib import PurePosixPath
class PathPreflightError(ValueError): pass

def preflight_path(root, relative_path):
    path=str(relative_path)
    parts=PurePosixPath(path).parts
    if not parts or path.startswith('/') or any(p in ('..', '.') for p in parts) or '\x00' in path:
        raise PathPreflightError('unsafe relative path')
    flags=os.O_RDONLY | getattr(os,'O_CLOEXEC',0) | getattr(os,'O_NOFOLLOW',0)
    directory_flags=flags | getattr(os,'O_DIRECTORY',0)
    fd=os.open(root,directory_flags)
    try:
        for i,part in enumerate(parts):
            next_fd=os.open(part,directory_flags if i<len(parts)-1 else flags,dir_fd=fd)
            os.close(fd); fd=next_fd
        stat=os.fstat(fd)
        return {'device':stat.st_dev,'inode':stat.st_ino,'mode':stat.st_mode}
    except (OSError,ValueError) as exc:
        raise PathPreflightError('path preflight failed') from exc
    finally:
        os.close(fd)
