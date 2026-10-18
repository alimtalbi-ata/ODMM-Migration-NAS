"""V212.0 conservative POSIX native staging. Author: Abdelhalim Talbi.

Linux/POSIX-only, single-file no-overwrite staging. Not an ACL-preserving NAS engine.
"""
import errno
import hashlib
import os
import secrets
import sqlite3
import stat
from pathlib import Path

class Blocked(RuntimeError):
    pass

FLAGS = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
DIRFLAGS = FLAGS | getattr(os, 'O_DIRECTORY', 0)

def _parts(name):
    if not isinstance(name, str) or not name or '\\' in name or '\x00' in name or name.startswith('/'):
        raise Blocked('INVALID_PATH')
    parts = name.split('/')
    if any(p in ('', '.', '..') for p in parts):
        raise Blocked('INVALID_PATH')
    return parts

def _parent(rootfd, parts):
    fd = os.dup(rootfd)
    try:
        for component in parts[:-1]:
            nextfd = os.open(component, DIRFLAGS, dir_fd=fd)
            os.close(fd)
            fd = nextfd
        return fd
    except Exception:
        os.close(fd)
        raise

def _digest(fd):
    h = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()

def _identity(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns

class SecureStaging:
    """No-overwrite, same-directory atomic publish, journalled; no cutover."""
    def __init__(self, source_root, target_root, journal):
        src = Path(source_root).resolve(strict=True)
        dst = Path(target_root).resolve(strict=True)
        if src == dst or src in dst.parents or dst in src.parents:
            raise Blocked('OVERLAPPING_ROOTS')
        self.srcfd = os.open(src, DIRFLAGS)
        try:
            self.dstfd = os.open(dst, DIRFLAGS)
            if os.fstat(self.srcfd).st_dev == os.fstat(self.dstfd).st_dev and os.fstat(self.srcfd).st_ino == os.fstat(self.dstfd).st_ino:
                raise Blocked('SAME_ROOT')
            self.db = sqlite3.connect(journal, timeout=5, isolation_level=None)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('CREATE TABLE IF NOT EXISTS secure_transfers (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN (\'PENDING\',\'VERIFIED\')), attempts INTEGER NOT NULL)')
        except Exception:
            os.close(self.srcfd)
            if hasattr(self, 'dstfd'): os.close(self.dstfd)
            raise

    def stage(self, name, *, fence):
        parts = _parts(name)
        if not callable(fence) or fence() is not True:
            raise Blocked('FENCE_REQUIRED')
        srcparent = _parent(self.srcfd, parts)
        try:
            dstparent = _parent(self.dstfd, parts)
        except Exception:
            os.close(srcparent)
            raise
        sourcefd = None
        tmp = None
        try:
            try:
                sourcefd = os.open(parts[-1], FLAGS | getattr(os, 'O_NONBLOCK', 0), dir_fd=srcparent)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise Blocked('SOURCE_SYMLINK') from exc
                raise
            before = os.fstat(sourcefd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise Blocked('SOURCE_NOT_EXCLUSIVE_REGULAR')
            try:
                os.stat(parts[-1], dir_fd=dstparent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Blocked('TARGET_EXISTS')
            digest = _digest(sourcefd)
            if _identity(before) != _identity(os.fstat(sourcefd)):
                raise Blocked('SOURCE_CHANGED')
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute("INSERT INTO secure_transfers(path,sha256,state,attempts) VALUES(?,?,'PENDING',1) ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256,state='PENDING',attempts=attempts+1", (name, digest))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            tmp = '.odmm-' + secrets.token_hex(16)
            outfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600, dir_fd=dstparent)
            try:
                os.lseek(sourcefd, 0, os.SEEK_SET)
                while True:
                    data = os.read(sourcefd, 1024 * 1024)
                    if not data: break
                    while data:
                        n = os.write(outfd, data)
                        if n <= 0: raise Blocked('SHORT_WRITE')
                        data = data[n:]
                os.fsync(outfd)
            finally:
                os.close(outfd)
            if _identity(before) != _identity(os.fstat(sourcefd)):
                raise Blocked('SOURCE_CHANGED')
            verifyfd = os.open(tmp, FLAGS, dir_fd=dstparent)
            try:
                if _digest(verifyfd) != digest:
                    raise Blocked('CHECKSUM_MISMATCH')
            finally:
                os.close(verifyfd)
            if fence() is not True:
                raise Blocked('FENCE_LOST')
            # Atomic publish without replacement: hard-link temp inode to final name.
            # This fails with EEXIST even when another process wins the race.
            try:
                os.link(tmp, parts[-1], src_dir_fd=dstparent, dst_dir_fd=dstparent, follow_symlinks=False)
            except FileExistsError as exc:
                raise Blocked('TARGET_RACE') from exc
            os.fsync(dstparent)
            os.unlink(tmp, dir_fd=dstparent)
            tmp = None
            os.fsync(dstparent)
            self.db.execute("UPDATE secure_transfers SET state='VERIFIED' WHERE path=? AND sha256=?", (name, digest))
            return {'path': name, 'sha256': digest, 'state': 'VERIFIED', 'engine': 'ODMM_NATIVE', 'cutover_authorized': False, 'acl_fidelity_verified': False}
        finally:
            if tmp is not None:
                try: os.unlink(tmp, dir_fd=dstparent)
                except FileNotFoundError: pass
            if sourcefd is not None: os.close(sourcefd)
            os.close(srcparent)
            os.close(dstparent)

    def pending(self):
        return [r[0] for r in self.db.execute("SELECT path FROM secure_transfers WHERE state='PENDING' ORDER BY path")]

    def close(self):
        self.db.close()
        os.close(self.srcfd)
        os.close(self.dstfd)
