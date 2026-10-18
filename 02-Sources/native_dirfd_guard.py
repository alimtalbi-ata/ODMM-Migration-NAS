"""Descriptor-relative, fail-closed POSIX path operations.

Building block for native migration. Not yet wired into the legacy copy path.
Only Linux/POSIX; directory entries are resolved using O_NOFOLLOW at each level.
"""
import contextlib
import os
import stat
from native_migration_errors import MigrationBlocked

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def parts_of(rel):
    if not isinstance(rel, str) or not rel or '\\' in rel or '\x00' in rel:
        raise MigrationBlocked('INVALID_PATH')
    parts = rel.split('/')
    if any(p in ('', '.', '..') for p in parts):
        raise MigrationBlocked('INVALID_PATH')
    return parts


@contextlib.contextmanager
def parent_fd(root, rel, *, root_fd=None):
    """Pin every parent inode, rejecting symlinks even during path replacement."""
    parts = parts_of(rel)
    fds = []
    try:
        fd = os.open(root, DIR_FLAGS) if root_fd is None else os.dup(root_fd)
        fds.append(fd)
        for part in parts[:-1]:
            fd = os.open(part, DIR_FLAGS, dir_fd=fd)
            fds.append(fd)
    except OSError as exc:
        raise MigrationBlocked('UNSAFE_DIRECTORY_OR_MISSING_PATH') from exc
    try:
        yield fd, parts[-1]
    finally:
        for fd in reversed(fds):
            os.close(fd)


def read_regular(root, rel):
    """Return bytes and metadata of a regular file; reject links and special files.

    For small validation fixtures only: production streaming must use fd operations.
    """
    with parent_fd(root, rel) as (directory, name):
        try:
            fd = os.open(name, FILE_FLAGS, dir_fd=directory)
        except OSError as exc:
            raise MigrationBlocked('UNSAFE_SOURCE') from exc
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise MigrationBlocked('NOT_REGULAR_FILE')
            if before.st_size > 1024 * 1024:
                raise MigrationBlocked('GUARD_READ_TOO_LARGE')
            data = bytearray()
            while len(data) <= 1024 * 1024:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(fd)
            if len(data) > 1024 * 1024 or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise MigrationBlocked('SOURCE_UNSTABLE')
            return bytes(data), before
        finally:
            os.close(fd)


def publish_noreplace(directory_fd, temp_name, final_name):
    """Atomic no-clobber hardlink publication within pinned destination directory."""
    for name in (temp_name, final_name):
        if len(parts_of(name)) != 1:
            raise MigrationBlocked('INVALID_LEAF')
    try:
        os.link(temp_name, final_name, src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd, follow_symlinks=False)
        os.fsync(directory_fd)
    except FileExistsError as exc:
        raise MigrationBlocked('TARGET_EXISTS') from exc
    except OSError as exc:
        raise MigrationBlocked('PUBLICATION_FAILED') from exc
