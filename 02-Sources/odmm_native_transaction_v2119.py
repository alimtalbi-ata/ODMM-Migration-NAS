"""Conservative POSIX file staging with SQLite recovery journal.

No ACL preservation guarantee, no production cutover. Author: Abdelhalim Talbi.
"""
import hashlib
import os
import sqlite3
import stat
import tempfile
from pathlib import Path

SCHEMA = '''CREATE TABLE IF NOT EXISTS transfers (
    relative_path TEXT PRIMARY KEY, source_sha256 TEXT NOT NULL,
    target_sha256 TEXT, state TEXT NOT NULL CHECK(state IN ('PENDING','VERIFIED')),
    attempt INTEGER NOT NULL DEFAULT 0
)'''

class MigrationBlocked(RuntimeError):
    pass


def _regular(root, relative, *, must_exist=True):
    if not isinstance(relative, str) or not relative or '\\' in relative or '\x00' in relative:
        raise MigrationBlocked('INVALID_PATH')
    parts = Path(relative).parts
    if Path(relative).is_absolute() or any(p in ('..', '.', '') for p in parts):
        raise MigrationBlocked('PATH_TRAVERSAL')
    current = Path(root)
    if current.is_symlink():
        raise MigrationBlocked('SYMLINK_ROOT')
    for part in parts[:-1]:
        current /= part
        if current.is_symlink() or not current.is_dir():
            raise MigrationBlocked('UNSAFE_PARENT')
    target = current / parts[-1]
    if target.is_symlink():
        raise MigrationBlocked('SYMLINK_FILE')
    if must_exist:
        st = target.lstat()
        if not stat.S_ISREG(st.st_mode):
            raise MigrationBlocked('NON_REGULAR_FILE')
    elif target.exists() and not stat.S_ISREG(target.lstat().st_mode):
        raise MigrationBlocked('NON_REGULAR_TARGET')
    return target


def _sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


class NativeStaging:
    """Opt-in staging only; target directories must preexist and be isolated."""
    def __init__(self, source_root, target_root, journal):
        self.source_root = Path(source_root).resolve(strict=True)
        self.target_root = Path(target_root).resolve(strict=True)
        if not self.source_root.is_dir() or not self.target_root.is_dir():
            raise MigrationBlocked('INVALID_ROOT')
        if self.source_root == self.target_root or self.source_root in self.target_root.parents or self.target_root in self.source_root.parents:
            raise MigrationBlocked('OVERLAPPING_ROOTS')
        self.db = sqlite3.connect(journal, isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute(SCHEMA)

    def stage(self, relative, *, fence, approve_overwrite=False):
        if not callable(fence) or fence() is not True:
            raise MigrationBlocked('FENCE_REQUIRED')
        source = _regular(self.source_root, relative)
        target = _regular(self.target_root, relative, must_exist=False)
        if target.exists() and not approve_overwrite:
            raise MigrationBlocked('TARGET_EXISTS')
        before = source.stat()
        digest = _sha(source)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('INSERT INTO transfers(relative_path,source_sha256,state,attempt) VALUES(?,?,?,1) '
                            'ON CONFLICT(relative_path) DO UPDATE SET source_sha256=excluded.source_sha256, '
                            'target_sha256=NULL,state=\'PENDING\',attempt=transfers.attempt+1',
                            (relative, digest, 'PENDING'))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(prefix='.odmm-stage-', dir=target.parent)
            with os.fdopen(fd, 'wb') as out, open(source, 'rb') as inp:
                for chunk in iter(lambda: inp.read(1024 * 1024), b''):
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            after = source.stat()
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise MigrationBlocked('SOURCE_CHANGED')
            if _sha(tmp) != digest:
                raise MigrationBlocked('CHECKSUM_MISMATCH')
            if fence() is not True:
                raise MigrationBlocked('FENCE_LOST')
            _regular(self.target_root, relative, must_exist=False)
            if target.exists() and not approve_overwrite:
                raise MigrationBlocked('TARGET_EXISTS')
            os.replace(tmp, target)
            tmp = None
            dirfd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
            if _sha(target) != digest:
                raise MigrationBlocked('TARGET_VERIFICATION_FAILED')
            self.db.execute('UPDATE transfers SET target_sha256=?,state=\'VERIFIED\' WHERE relative_path=?', (digest, relative))
            return {'path': relative, 'sha256': digest, 'state': 'VERIFIED', 'cutover_authorized': False,
                    'acl_fidelity_verified': False, 'engine': 'ODMM_NATIVE'}
        finally:
            if tmp is not None:
                os.unlink(tmp)

    def pending(self):
        return [r[0] for r in self.db.execute("SELECT relative_path FROM transfers WHERE state='PENDING' ORDER BY relative_path")]

    def close(self):
        self.db.close()
