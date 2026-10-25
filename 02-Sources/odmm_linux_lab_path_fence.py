"""Descriptor-anchored ancestor checks for the isolated POSIX copy laboratory.

Not a distributed lease, atomic snapshot, or defense against ABA replace/restore.
Author: Abdelhalim Talbi.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import stat


class PathFenceError(ValueError):
    pass


@contextmanager
def pin_parent_chain(path):
    """Yield (parent_fd, check_chain), pinning every ancestor from '/'.

    Call check_chain before and after descriptor-relative I/O. Symlink
    ancestors and lexical '..' are rejected fail-closed.
    """
    original = Path(path)
    if ".." in original.parts:
        raise PathFenceError("PARENT_TRAVERSAL_REFUSED")
    absolute = Path(os.path.abspath(original))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fds = []
    edges = []
    try:
        fds.append(os.open("/", flags))
        for component in absolute.parent.parts[1:]:
            parent_fd = fds[-1]
            child_fd = os.open(component, flags, dir_fd=parent_fd)
            fds.append(child_fd)
            edges.append((parent_fd, component, child_fd))

        def check_chain():
            for parent_fd, component, child_fd in edges:
                pinned = os.fstat(child_fd)
                current = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
                if (not stat.S_ISDIR(current.st_mode) or
                    (pinned.st_dev, pinned.st_ino) != (current.st_dev, current.st_ino)):
                    raise PathFenceError("ANCESTOR_IDENTITY_CHANGED")

        check_chain()
        yield fds[-1], check_chain
        check_chain()
    finally:
        for fd in reversed(fds):
            os.close(fd)
