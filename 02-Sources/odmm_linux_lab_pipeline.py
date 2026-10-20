"""Isolated Linux lab copy pipeline; no network/NAS integration.

Requires exclusive lease, durable intent and independent content verification.
Author: Abdelhalim Talbi.
"""
import os
import shutil
import stat
from pathlib import Path
from odmm_linux_datamover_intents import prepare, mark_in_flight, record_verification
from odmm_linux_lab_verifier import verify_pair, VerificationError

class LabPipelineError(RuntimeError):
    pass

def run_lab_copy(db, *, intent_id, task_id, owner, token, source, target, now=None, fault_at=None):
    """Copy one regular local file to an exclusive new target.

    Never overwrites. On failure after IN_FLIGHT, recovery must quarantine the
    intent; caller must not automatically retry. Not a distributed NAS fence.
    """
    if fault_at not in (None, "after_intent", "after_copy_fsync", "during_copy"):
        raise ValueError("INVALID_FAULT_POINT")
    source, target = Path(source), Path(target)
    if source.is_symlink() or not source.is_file() or target.is_symlink():
        raise LabPipelineError("INVALID_SOURCE_OR_TARGET")
    if target.exists():
        raise LabPipelineError("TARGET_ALREADY_EXISTS")
    payload = {"kind": "local-lab-copy-v1", "source": str(source.resolve()),
               "target": str(target.absolute())}
    digest = prepare(db, intent_id, task_id, owner, token, payload, now=now)
    mark_in_flight(db, intent_id, task_id, owner, token, now=now)
    if fault_at == "after_intent":
        raise LabPipelineError("INJECTED_AFTER_INTENT")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = None
    source_fd = None
    try:
        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        source_before = os.fstat(source_fd)
        if not stat.S_ISREG(source_before.st_mode):
            raise LabPipelineError("SOURCE_NOT_REGULAR")
        fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as out:
            fd = None
            with os.fdopen(os.dup(source_fd), "rb") as inp:
                if fault_at == "during_copy":
                    block = inp.read(4096)
                    if block:
                        out.write(block)
                        out.flush()
                        os.fsync(out.fileno())
                    raise LabPipelineError("INJECTED_DURING_COPY")
                shutil.copyfileobj(inp, out, length=1024 * 1024)
            source_after = os.fstat(source_fd)
            if (source_before.st_dev, source_before.st_ino, source_before.st_size, source_before.st_mtime_ns) != (source_after.st_dev, source_after.st_ino, source_after.st_size, source_after.st_mtime_ns):
                raise LabPipelineError("SOURCE_CHANGED_DURING_COPY")
            out.flush()
            os.fsync(out.fileno())
        if fault_at == "after_copy_fsync":
            raise LabPipelineError("INJECTED_AFTER_COPY_FSYNC")
        os.chmod(target, stat.S_IMODE(source_before.st_mode))
        dirfd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        evidence = verify_pair(source, target)
        record_verification(db, intent_id, task_id, owner, token, digest, now=now)
        return {"intent_id": intent_id, "state": "VERIFIED", "evidence": evidence,
                "production_nas_qualified": False}
    except BaseException:
        # Never clean up target or mark VERIFIED: it may have been partially written.
        # IN_FLIGHT must be quarantined by recovery.
        raise
    finally:
        if fd is not None:
            os.close(fd)
        if source_fd is not None:
            os.close(source_fd)
