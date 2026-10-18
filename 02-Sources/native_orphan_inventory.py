"""Read-only inventory of abandoned native temporary files.

Never delete automatically: a file may belong to a live worker. Caller must
perform independent ownership/liveness checks before any manual cleanup.
"""
import os
import re
import stat
from native_dirfd_guard import parent_fd
from native_migration_errors import MigrationBlocked

_PATTERN = re.compile(r'^\.odmm-[0-9a-f]{32}\.part$')

def inspect_orphans(engine, relative_directory=''):
    """Inspect one target directory via pinned dir_fd; no traversal or writes."""
    if relative_directory and (not isinstance(relative_directory, str) or relative_directory.startswith('/') or any(x in ('', '.', '..') for x in relative_directory.split('/')) or '\\' in relative_directory or '\x00' in relative_directory):
        raise MigrationBlocked('INVALID_DIRECTORY')
    with engine._exclusive():
        engine._check_roots()
        if relative_directory:
            # parent_fd opens the full directory as a parent of a dummy basename
            with parent_fd(engine.target, relative_directory + '/.probe', root_fd=engine._root_fds[1]) as (directory, _):
                return _scan(directory, relative_directory)
        return _scan(engine._root_fds[1], '')

def _scan(directory, prefix):
    results=[]
    for name in os.listdir(directory):
        if not _PATTERN.fullmatch(name):
            continue
        st=os.stat(name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            raise MigrationBlocked('UNSAFE_ORPHAN_ENTRY')
        results.append({'path': (prefix + '/' if prefix else '') + name,
                        'size': st.st_size, 'mtime_ns': st.st_mtime_ns,
                        'status': 'REVIEW_REQUIRED', 'auto_delete_authorized': False,
                        'cutover_authorized': False})
    return sorted(results, key=lambda r:r['path'])
