"""Conservative native POSIX file migration prototype, not NAS/ACL qualification.

Only regular files, no symlinks, no overwrites. SQLite tracks verified files.
"""
import hashlib
import contextlib
import fcntl
import os
import sqlite3
import stat
import uuid
from pathlib import Path
from native_dirfd_guard import parent_fd, FILE_FLAGS, publish_noreplace

from native_migration_errors import MigrationBlocked

CHUNK = 1024 * 1024

def _regular(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode):
            raise MigrationBlocked('NOT_REGULAR_FILE')
        return fd, s
    except BaseException:
        os.close(fd)
        raise

def _identity(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

def _verified_hash(fd, *, expected=None):
    """Hash a pinned descriptor and reject observable concurrent modifications.

    This does not provide snapshot isolation against malicious writers that restore
    timestamps or against in-place changes between sampling points.
    """
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise MigrationBlocked('NOT_REGULAR_FILE')
    if expected is not None and _identity(before) != _identity(expected):
        raise MigrationBlocked('FILE_CHANGED_BEFORE_HASH')
    digest = _hash_fd(fd)
    after = os.fstat(fd)
    if _identity(before) != _identity(after):
        raise MigrationBlocked('FILE_CHANGED_DURING_HASH')
    return digest

def _hash_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    while True:
        b = os.read(fd, CHUNK)
        if not b:
            break
        h.update(b)
    return h.hexdigest()

class NativePosixMigration:
    def __init__(self, source, target, database, *, copy_user_xattrs=False):
        self.copy_user_xattrs = copy_user_xattrs is True
        # Reject symlinked roots before canonicalization; do not silently follow them.
        for root in (source, target):
            candidate = Path(os.path.abspath(root))
            if candidate.is_symlink():
                raise MigrationBlocked('SYMLINK_ROOT')
        self.source = Path(source).resolve(strict=True)
        self.target = Path(target).resolve(strict=True)
        if not self.source.is_dir() or not self.target.is_dir() or self.source == self.target:
            raise MigrationBlocked('INVALID_ROOTS')
        if self.source in self.target.parents or self.target in self.source.parents:
            raise MigrationBlocked('OVERLAPPING_ROOTS')
        self.dbpath = Path(database).resolve()
        if self.dbpath.is_relative_to(self.source) or self.dbpath.is_relative_to(self.target):
            raise MigrationBlocked('DATABASE_INSIDE_TREE')
        self._root_fds = []
        try:
            for root in (self.source, self.target):
                self._root_fds.append(os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
        except BaseException:
            for fd in self._root_fds:
                os.close(fd)
            raise
        try:
            self.db = sqlite3.connect(self.dbpath, isolation_level=None, timeout=5)
        except BaseException:
            for fd in self._root_fds:
                os.close(fd)
            raise
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, size INTEGER NOT NULL, sha256 TEXT NOT NULL, mode INTEGER NOT NULL, mtime_ns INTEGER NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS xattr_manifest (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS intents (path TEXT PRIMARY KEY, size INTEGER NOT NULL, sha256 TEXT NOT NULL, mode INTEGER NOT NULL, mtime_ns INTEGER NOT NULL)')
        self.lockfd = os.open(str(self.dbpath) + '.native.lock', os.O_CREAT | os.O_RDWR, 0o600)

    def close(self):
        try:
            self.db.close()
        finally:
            try:
                os.close(self.lockfd)
            finally:
                for fd in self._root_fds:
                    os.close(fd)
                self._root_fds.clear()

    @contextlib.contextmanager
    def _exclusive(self):
        fcntl.flock(self.lockfd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(self.lockfd, fcntl.LOCK_UN)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _check_roots(self):
        for root, pinned in zip((self.source, self.target), self._root_fds):
            try:
                fresh = os.stat(root, follow_symlinks=False)
            except OSError as exc:
                raise MigrationBlocked('ROOT_MISSING_OR_REPLACED') from exc
            old = os.fstat(pinned)
            if not stat.S_ISDIR(fresh.st_mode) or (fresh.st_dev, fresh.st_ino) != (old.st_dev, old.st_ino):
                raise MigrationBlocked('ROOT_REPLACED')

    def _paths(self, rel):
        if not isinstance(rel, str) or not rel or '\\' in rel or '\x00' in rel:
            raise MigrationBlocked('INVALID_PATH')
        p = Path(rel)
        if p.is_absolute() or any(x in ('', '.', '..') for x in rel.split('/')):
            raise MigrationBlocked('INVALID_PATH')
        src = self.source / p
        dst = self.target / p
        for root, candidate in ((self.source, src), (self.target, dst)):
            current = root
            for part in p.parts[:-1]:
                current = current / part
                if current.is_symlink():
                    raise MigrationBlocked('SYMLINK_DIRECTORY')
            if candidate.is_symlink():
                raise MigrationBlocked('SYMLINK_FILE')
        return src, dst

    def copy(self, rel, *, after_temp_sync=None, after_publish=None):
        with self._exclusive():
            self._check_roots()
            return self._copy_locked(rel, after_temp_sync=after_temp_sync, after_publish=after_publish)

    def _open_file(self, directory, name):
        try:
            fd = os.open(name, FILE_FLAGS, dir_fd=directory)
        except OSError as exc:
            raise MigrationBlocked('UNSAFE_FILE_OR_MISSING') from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise MigrationBlocked('NOT_REGULAR_FILE')
            return fd, st
        except BaseException:
            os.close(fd)
            raise

    def _check_source_entry(self, directory, name, pinned_fd):
        try:
            entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except OSError as exc:
            raise MigrationBlocked('SOURCE_ENTRY_REPLACED') from exc
        pinned = os.fstat(pinned_fd)
        if not stat.S_ISREG(entry.st_mode) or (entry.st_dev, entry.st_ino) != (pinned.st_dev, pinned.st_ino):
            raise MigrationBlocked('SOURCE_ENTRY_REPLACED')

    def _check_parent_identity(self, root, rel, pinned_fd):
        self._check_roots()
        # Fail closed if a parent was renamed or replaced during an operation.
        with parent_fd(root, rel, root_fd=self._root_fds[0 if root == self.source else 1]) as (fresh, _):
            old = os.fstat(pinned_fd)
            new = os.fstat(fresh)
            if (old.st_dev, old.st_ino) != (new.st_dev, new.st_ino):
                raise MigrationBlocked('DIRECTORY_REPLACED')

    def _read_xattrs(self, fd):
        """Read only user.* attributes from a pinned descriptor; ACL/security namespaces fail closed."""
        if not hasattr(os, 'listxattr') or not hasattr(os, 'getxattr'):
            raise MigrationBlocked('XATTR_INSPECTION_UNAVAILABLE')
        try:
            names = os.listxattr(fd)
            if any(not n.startswith('user.') for n in names):
                raise MigrationBlocked('UNSUPPORTED_XATTR_OR_ACL')
            if names and not self.copy_user_xattrs:
                raise MigrationBlocked('UNSUPPORTED_XATTR_OR_ACL')
            values = {n: os.getxattr(fd, n) for n in sorted(names)}
            if set(os.listxattr(fd)) != set(names):
                raise MigrationBlocked('XATTR_CHANGED_DURING_READ')
            return values
        except (OSError, TypeError, ValueError) as exc:
            raise MigrationBlocked('XATTR_INSPECTION_FAILED') from exc

    def _reject_unhandled_xattrs(self, fd):
        return self._read_xattrs(fd)

    @staticmethod
    def _xattr_digest(values):
        h = hashlib.sha256()
        for name, value in sorted(values.items()):
            encoded = name.encode('utf-8')
            h.update(len(encoded).to_bytes(4, 'big') + encoded)
            h.update(len(value).to_bytes(8, 'big') + value)
        return h.hexdigest()

    def _check_xattr_pair(self, source_fd, target_fd, rel):
        source = self._read_xattrs(source_fd)
        target = self._read_xattrs(target_fd)
        if source != target:
            raise MigrationBlocked('XATTR_DRIFT')
        expected = self.db.execute('SELECT sha256 FROM xattr_manifest WHERE path=?', (rel,)).fetchone()
        if expected is None:
            if source:
                raise MigrationBlocked('XATTR_MANIFEST_MISSING')
        elif self._xattr_digest(source) != expected[0]:
            raise MigrationBlocked('XATTR_MANIFEST_DRIFT')

    def _copy_locked(self, rel, *, after_temp_sync=None, after_publish=None):
        with parent_fd(self.source, rel, root_fd=self._root_fds[0]) as (src_dir, src_name), parent_fd(self.target, rel, root_fd=self._root_fds[1]) as (dst_dir, dst_name):
            fd, before = self._open_file(src_dir, src_name)
            tmp_name = None
            try:
                source_xattrs = self._read_xattrs(fd)
                row = self.db.execute('SELECT size,sha256,mode,mtime_ns FROM files WHERE path=?', (rel,)).fetchone()
                if row is not None:
                    outfd, st = self._open_file(dst_dir, dst_name)
                    try:
                        if (st.st_size, stat.S_IMODE(st.st_mode), st.st_mtime_ns) != (row[0], row[2], row[3]) or _verified_hash(outfd, expected=st) != row[1]:
                            raise MigrationBlocked('COMMITTED_TARGET_CHANGED')
                        self._check_xattr_pair(fd, outfd, rel)
                        self._check_source_entry(dst_dir, dst_name, outfd)
                    finally:
                        os.close(outfd)
                    if before.st_size != row[0] or _verified_hash(fd, expected=before) != row[1]:
                        raise MigrationBlocked('COMMITTED_SOURCE_CHANGED')
                    self._check_source_entry(src_dir, src_name, fd)
                    self._check_parent_identity(self.source, rel, src_dir)
                    self._check_parent_identity(self.target, rel, dst_dir)
                    return {'status':'ALREADY_VERIFIED', 'path':rel, 'sha256':row[1], 'cutover_authorized':False}
                if self.db.execute('SELECT 1 FROM intents WHERE path=?', (rel,)).fetchone():
                    raise MigrationBlocked('PENDING_INTENT_REQUIRES_RECONCILIATION')
                try:
                    os.stat(dst_name, dir_fd=dst_dir, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise MigrationBlocked('TARGET_EXISTS')
                mode = stat.S_IMODE(before.st_mode)
                tmp_name = '.odmm-' + uuid.uuid4().hex + '.part'
                outfd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dst_dir)
                digest = hashlib.sha256()
                try:
                    while True:
                        data = os.read(fd, CHUNK)
                        if not data:
                            break
                        digest.update(data)
                        view = memoryview(data)
                        while view:
                            view = view[os.write(outfd, view):]
                    if self._read_xattrs(fd) != source_xattrs:
                        raise MigrationBlocked('XATTR_CHANGED_DURING_COPY')
                    for name, value in source_xattrs.items():
                        try:
                            os.setxattr(outfd, name, value)
                        except (OSError, TypeError, ValueError) as exc:
                            raise MigrationBlocked('XATTR_COPY_FAILED') from exc
                    if self._read_xattrs(outfd) != source_xattrs:
                        raise MigrationBlocked('XATTR_COPY_MISMATCH')
                    os.fchmod(outfd, mode)
                    os.utime(outfd, ns=(before.st_atime_ns, before.st_mtime_ns))
                    os.fsync(outfd)
                finally:
                    os.close(outfd)
                after = os.fstat(fd)
                if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns):
                    raise MigrationBlocked('SOURCE_CHANGED_DURING_COPY')
                if after_temp_sync:
                    after_temp_sync()
                latest = os.fstat(fd)
                if (latest.st_size, latest.st_mtime_ns, latest.st_ctime_ns) != (before.st_size, before.st_mtime_ns, before.st_ctime_ns):
                    raise MigrationBlocked('SOURCE_CHANGED_BEFORE_PUBLICATION')
                self._check_source_entry(src_dir, src_name, fd)
                if self._read_xattrs(fd) != source_xattrs:
                    raise MigrationBlocked('XATTR_CHANGED_BEFORE_PUBLICATION')
                self._check_parent_identity(self.source, rel, src_dir)
                self._check_parent_identity(self.target, rel, dst_dir)
                self._check_roots()
                self.db.execute('INSERT INTO intents VALUES (?,?,?,?,?)', (rel, before.st_size, digest.hexdigest(), mode, before.st_mtime_ns))
                publish_noreplace(dst_dir, tmp_name, dst_name)
                os.unlink(tmp_name, dir_fd=dst_dir)
                os.fsync(dst_dir)
                tmp_name = None
                if after_publish:
                    after_publish()
                self._check_parent_identity(self.source, rel, src_dir)
                self._check_parent_identity(self.target, rel, dst_dir)
                self._check_source_entry(src_dir, src_name, fd)
                if self._read_xattrs(fd) != source_xattrs:
                    raise MigrationBlocked('XATTR_CHANGED_AFTER_PUBLICATION')
                # Ensure source is still the same inode and content before commit.
                latest = os.fstat(fd)
                if (latest.st_dev, latest.st_ino, latest.st_size, latest.st_mtime_ns, latest.st_ctime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns):
                    raise MigrationBlocked('SOURCE_CHANGED_AFTER_PUBLICATION')
                self.db.execute('BEGIN IMMEDIATE')
                try:
                    self.db.execute('INSERT INTO files VALUES (?,?,?,?,?)', (rel, before.st_size, digest.hexdigest(), mode, before.st_mtime_ns))
                    self.db.execute('INSERT INTO xattr_manifest VALUES (?,?)', (rel, self._xattr_digest(source_xattrs)))
                    self.db.execute('DELETE FROM intents WHERE path=?', (rel,))
                    self.db.execute('COMMIT')
                except BaseException:
                    self.db.execute('ROLLBACK')
                    raise
                return {'status':'COPIED_VERIFIED', 'path':rel, 'sha256':digest.hexdigest(), 'cutover_authorized':False}
            finally:
                os.close(fd)
                if tmp_name is not None:
                    try:
                        os.unlink(tmp_name, dir_fd=dst_dir)
                    except FileNotFoundError:
                        pass

    def cleanup_orphan_temps(self, rel, *, operator_confirmed=False):
        """Remove only ODMM temporary regular files in a pinned target directory.

        Explicit opt-in; refuse when the path has an unresolved publication intent.
        Never follow symlinks, and never remove published destination files.
        """
        if operator_confirmed is not True:
            raise MigrationBlocked('OPERATOR_CONFIRMATION_REQUIRED')
        with self._exclusive():
            self._check_roots()
            self._paths(rel)
            if self.db.execute('SELECT 1 FROM intents WHERE path=?', (rel,)).fetchone():
                raise MigrationBlocked('PENDING_INTENT_REQUIRES_RECONCILIATION')
            with parent_fd(self.target, rel, root_fd=self._root_fds[1]) as (directory, _):
                self._check_parent_identity(self.target, rel, directory)
                removed = []
                for name in os.listdir(directory):
                    if not (name.startswith('.odmm-') and name.endswith('.part') and len(name) == 43
                            and all(c in '0123456789abcdef' for c in name[6:-5])):
                        continue
                    st = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                        raise MigrationBlocked('UNSAFE_TEMP_ENTRY')
                    os.unlink(name, dir_fd=directory)
                    removed.append(name)
                if removed:
                    os.fsync(directory)
                return {'status':'ORPHAN_TEMPS_CLEANED', 'removed':sorted(removed), 'cutover_authorized':False}

    def verify(self, rel):
        with self._exclusive():
            self._check_roots()
            with parent_fd(self.source, rel, root_fd=self._root_fds[0]) as (src_dir, src_name), parent_fd(self.target, rel, root_fd=self._root_fds[1]) as (dst_dir, dst_name):
                row = self.db.execute('SELECT size,sha256,mode,mtime_ns FROM files WHERE path=?', (rel,)).fetchone()
                if row is None:
                    raise MigrationBlocked('NOT_COMMITTED')
                attrs_seen = []
                for directory, name, target in ((src_dir, src_name, False), (dst_dir, dst_name, True)):
                    fd, st = self._open_file(directory, name)
                    try:
                        attrs_seen.append(self._read_xattrs(fd))
                        if st.st_size != row[0] or _verified_hash(fd, expected=st) != row[1]:
                            raise MigrationBlocked('CONTENT_DRIFT')
                        if target and (stat.S_IMODE(st.st_mode), st.st_mtime_ns) != (row[2], row[3]):
                            raise MigrationBlocked('METADATA_DRIFT')
                        self._check_source_entry(directory, name, fd)
                    finally:
                        os.close(fd)
                if attrs_seen[0] != attrs_seen[1]:
                    raise MigrationBlocked('XATTR_DRIFT')
                manifest = self.db.execute('SELECT sha256 FROM xattr_manifest WHERE path=?', (rel,)).fetchone()
                if attrs_seen[0] and (manifest is None or manifest[0] != self._xattr_digest(attrs_seen[0])):
                    raise MigrationBlocked('XATTR_MANIFEST_DRIFT')
                self._check_parent_identity(self.source, rel, src_dir)
                self._check_parent_identity(self.target, rel, dst_dir)
                return {'status':'VERIFIED_POSIX_SUBSET_ONLY', 'path':rel, 'cutover_authorized':False}

    def reconcile(self, rel, *, operator_confirmed=False):
        if operator_confirmed is not True:
            raise MigrationBlocked('OPERATOR_CONFIRMATION_REQUIRED')
        with self._exclusive():
            self._check_roots()
            with parent_fd(self.source, rel, root_fd=self._root_fds[0]) as (src_dir, src_name), parent_fd(self.target, rel, root_fd=self._root_fds[1]) as (dst_dir, dst_name):
                row = self.db.execute('SELECT size,sha256,mode,mtime_ns FROM intents WHERE path=?', (rel,)).fetchone()
                if row is None:
                    raise MigrationBlocked('NO_PENDING_INTENT')
                attrs_seen = []
                for directory, name, target in ((src_dir, src_name, False), (dst_dir, dst_name, True)):
                    fd, st = self._open_file(directory, name)
                    try:
                        attrs_seen.append(self._read_xattrs(fd))
                        if st.st_size != row[0] or _verified_hash(fd, expected=st) != row[1]:
                            raise MigrationBlocked('RECONCILIATION_CONTENT_MISMATCH')
                        if target and (stat.S_IMODE(st.st_mode), st.st_mtime_ns) != (row[2], row[3]):
                            raise MigrationBlocked('RECONCILIATION_METADATA_MISMATCH')
                        self._check_source_entry(directory, name, fd)
                    finally:
                        os.close(fd)
                self._check_parent_identity(self.source, rel, src_dir)
                self._check_parent_identity(self.target, rel, dst_dir)
                if attrs_seen[0] != attrs_seen[1]:
                    raise MigrationBlocked('XATTR_DRIFT')
                self.db.execute('BEGIN IMMEDIATE')
                try:
                    self.db.execute('INSERT INTO xattr_manifest VALUES (?,?)', (rel, self._xattr_digest(attrs_seen[0])))
                    self.db.execute('INSERT INTO files VALUES (?,?,?,?,?)', (rel, *row))
                    self.db.execute('DELETE FROM intents WHERE path=?', (rel,))
                    self.db.execute('COMMIT')
                except BaseException:
                    self.db.execute('ROLLBACK')
                    raise
                return {'status':'RECONCILED_VERIFIED', 'path':rel, 'cutover_authorized':False}
