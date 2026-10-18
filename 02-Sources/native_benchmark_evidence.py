"""V192.4: one locked snapshot for HMAC diagnosis and immutable evidence backup.

No journal repair, truncation or migration is permitted.
"""
import fcntl
import hashlib
import os
import secrets
from pathlib import Path
from native_benchmark_integrity import _open, _read_locked, GENESIS
from native_benchmark_authenticated import _check


def snapshot_evidence(path, *, keys, backup_path=None, trusted_head=None):
    """Inspect one locked byte snapshot; optionally create an exclusive backup.

    Backup creation is fail-closed: existing targets are never overwritten. A
    backup is an investigation copy, not a verified or trusted journal.
    """
    try:
        fd = _open(path, readonly=True)
    except FileNotFoundError:
        return {'schema':'odmm.benchmark.evidence.v1','status':'EMPTY',
                'reason':'JOURNAL_ABSENT','evidence_sha256':None,'evidence_bytes':0,
                'backup_created':False,'mutations_performed':False,'cutover_authorized':False}
    backup_created = False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        raw = None
        try:
            raw = _read_locked(fd)
        except ValueError:
            # Incomplete tails still need evidence preservation. Read under
            # the same lock and apply a strict size limit.
            os.lseek(fd, 0, os.SEEK_SET)
            chunks=[]; size=0
            while True:
                part=os.read(fd,65536)
                if not part: break
                size+=len(part)
                if size>20_000_000: raise ValueError('EVIDENCE_TOO_LARGE')
                chunks.append(part)
            raw=b''.join(chunks)
        digest=hashlib.sha256(raw).hexdigest()
        try:
            records, active, head = _check(raw,keys,trusted_head=trusted_head)
            status='VERIFIED' if records else 'EMPTY'
            reason='AUTHENTICATED_CHAIN_VALID' if records else 'JOURNAL_EMPTY'
        except (ValueError,TypeError,KeyError):
            status='BLOCKED';reason='INTEGRITY_OR_KEY_FAILURE'
            active=None;head=None
        if backup_path is not None:
            _publish_backup(backup_path, raw, digest, os.fstat(fd))
            backup_created = True
        return {'schema':'odmm.benchmark.evidence.v1','status':status,'reason':reason,
                'evidence_sha256':digest,'evidence_bytes':len(raw),
                'head_sha256':head,'active_key_id':active,
                'backup_created':backup_created,'mutations_performed':False,
                'cutover_authorized':False,'next_step':'HUMAN_REVIEW' if status=='BLOCKED' else 'NONE'}
    finally:os.close(fd)


def _publish_backup(backup_path, raw, digest, source_stat):
    """Stage, fsync and verify before no-overwrite hard-link publication.

    An abrupt crash can leave a private .odmm-stage-* file; never remove it
    automatically, because it may contain forensic evidence.
    """
    dest = Path(os.path.abspath(backup_path))
    if not dest.name or dest.name in ('.', '..'):
        raise ValueError('BACKUP_INVALID_NAME')
    parts = dest.parent.parts
    directory = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY)
    stage = None
    published = False
    try:
        for part in parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        # Existing target must never be overwritten, even on failure.
        try:
            existing = os.stat(dest.name, dir_fd=directory, follow_symlinks=False)
            if (existing.st_dev, existing.st_ino) == (source_stat.st_dev, source_stat.st_ino):
                raise ValueError('BACKUP_SAME_AS_SOURCE')
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError('BACKUP_TARGET_EXISTS')
        stage = '.odmm-stage-' + secrets.token_hex(16)
        out = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            if (os.fstat(out).st_dev, os.fstat(out).st_ino) == (source_stat.st_dev, source_stat.st_ino):
                raise ValueError('BACKUP_SAME_AS_SOURCE')
            pos = 0
            while pos < len(raw):
                n = os.write(out, raw[pos:])
                if n <= 0: raise OSError('BACKUP_WRITE_FAILED')
                pos += n
            os.fsync(out)
        finally:
            os.close(out)
        verify = os.open(stage, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            h = hashlib.sha256()
            while True:
                chunk = os.read(verify, 65536)
                if not chunk: break
                h.update(chunk)
            if h.hexdigest() != digest: raise ValueError('BACKUP_VERIFY_FAILED')
        finally:
            os.close(verify)
        os.link(stage, dest.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        published = True
        os.fsync(directory)
        os.unlink(stage, dir_fd=directory)
        stage = None
        os.fsync(directory)
    except BaseException:
        # A published target is intentionally preserved even if fsync fails.
        # Never claim a successful backup unless both syncs complete.
        if stage is not None and not published:
            try: os.unlink(stage, dir_fd=directory)
            except OSError: pass
        raise
    finally:
        os.close(directory)
