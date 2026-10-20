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

def run_lab_copy(db, *, intent_id, task_id, owner, token, source, target, now=None):
    """Copy one regular local file to an exclusive new target.

    Never overwrites. On failure after IN_FLIGHT, recovery must quarantine the
    intent; caller must not automatically retry. Not a distributed NAS fence.
    """
    source, target = Path(source), Path(target)
    if source.is_symlink() or not source.is_file() or target.is_symlink():
        raise LabPipelineError("INVALID_SOURCE_OR_TARGET")
    if target.exists():
        raise LabPipelineError("TARGET_ALREADY_EXISTS")
    payload = {"kind": "local-lab-copy-v1", "source": str(source.resolve()),
               "target": str(target.absolute())}
    digest = prepare(db, intent_id, task_id, owner, token, payload, now=now)
    mark_in_flight(db, intent_id, task_id, owner, token, now=now)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = None
    try:
        fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as out:
            fd = None
            with open(source, "rb") as inp:
                if not stat.S_ISREG(os.fstat(inp.fileno()).st_mode):
                    raise LabPipelineError("SOURCE_NOT_REGULAR")
                shutil.copyfileobj(inp, out, length=1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(target, stat.S_IMODE(source.stat().st_mode))
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
