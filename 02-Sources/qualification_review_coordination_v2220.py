"""Cross-process review serialization and operator-supervised anchor recovery.
Author: Abdelhalim Talbi. File locks require a shared, reliable filesystem.
"""
import os
import time
from contextlib import contextmanager
from pathlib import Path
from fastapi import HTTPException
from qualification_review_gate_v2218 import enforce_review_gate
from qualification_review_security_v2217 import write_anchor, verify_anchor, review_head
from qualification_decisions_v2215 import append_review
from qualification_recovery_audit_v2225 import append_recovery_audit
from qualification_recovery_custody_v2226 import verify_custody, export_custody
from qualification_external_receipt_v2228 import verify_external_receipt
from qualification_custody_ack_v2229 import read_ack_state, mark_pending

@contextmanager
def exclusive_lock(lock_path, *, timeout=5.0):
    """Fail closed: never automatically remove stale locks; operator intervention required."""
    path = Path(lock_path)
    if not path.parent.is_dir():
        raise ValueError('LOCK_DIRECTORY_MISSING')
    deadline = time.monotonic() + timeout
    fd = None
    while fd is None:
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise HTTPException(503, 'REVIEW_LOCK_BUSY_OR_STALE')
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(f'pid={os.getpid()}\n')
            handle.flush()
            os.fsync(handle.fileno())
        yield
    finally:
        path.unlink()


def append_review_coordinated(db_path, anchor_path, dossier, *, identity, action, reason, secret, lock_path=None, request_id=None):
    """Serializes cooperating writers across processes; never auto-replays a committed event."""
    lock_path = lock_path or str(anchor_path) + '.lock'
    with exclusive_lock(lock_path):
        reviewer = enforce_review_gate(identity, review_db_path=db_path,
                                       anchor_path=anchor_path, secret=secret)
        event = append_review(db_path, dossier, action=action, reviewer=reviewer,
                              reason=reason, secret=secret, request_id=request_id)
        try:
            write_anchor(db_path, anchor_path, secret)
            verify_anchor(db_path, anchor_path, secret)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise HTTPException(503, 'REVIEW_COMMITTED_ANCHOR_REFRESH_FAILED_MANUAL_RECOVERY') from exc
        return event


def recover_anchor_supervised(db_path, anchor_path, *, secret, expected_head_mac, expected_count, lock_path=None, audit_path=None, operator=None, custody_path=None, external_receipt_path=None, custodian_key=None, custodian=None, custody_ack_path=None, secure_custody=False, custody_witness_path=None):
    """Recovery requires an independently confirmed head MAC/count, never blind reanchoring."""
    with exclusive_lock(lock_path or str(anchor_path) + '.lock'):
        if secure_custody and (custody_ack_path is None or custody_witness_path is None or custody_path is None or audit_path is None):
            raise ValueError('SECURE_CUSTODY_CONFIGURATION_REQUIRED')
        if custody_ack_path is not None:
            try:
                ack = read_ack_state(custody_ack_path, secret=secret,
                                     witness_path=custody_witness_path if secure_custody else None)
            except ValueError as exc:
                # A missing/unreadable state cannot be treated as confirmed.
                raise ValueError('CUSTODY_ACK_STATE_UNVERIFIED') from exc
            if ack['status'] != 'CUSTODY_CONFIRMED':
                raise ValueError('PENDING_CUSTODY_ACK')
            if custody_path is None or audit_path is None or verify_custody(audit_path, custody_path, secret) != ack['head']:
                raise ValueError('CUSTODY_ACK_HEAD_MISMATCH')
        head = review_head(db_path, secret)
        if (not isinstance(expected_head_mac, str) or
                head['head_mac'] != expected_head_mac or
                type(expected_count) is not int or head['count'] != expected_count):
            raise ValueError('INDEPENDENT_HEAD_CONFIRMATION_MISMATCH')
        if external_receipt_path is not None:
            if custody_path is None or audit_path is None or not custodian_key or not custodian:
                raise ValueError('EXTERNAL_RECEIPT_CONFIGURATION_INCOMPLETE')
            verify_external_receipt(audit_path, custody_path, external_receipt_path,
                                    secret=secret, custodian_key=custodian_key, custodian=custodian)
        if custody_path is not None:
            if audit_path is None:
                raise ValueError('RECOVERY_CUSTODY_REQUIRES_AUDIT')
            # Fail closed on absent, tampered or rolled-back independently retained evidence.
            verify_custody(audit_path, custody_path, secret)
        if audit_path is not None:
            append_recovery_audit(audit_path, secret, operator=operator, confirmed_head=head)
            if custody_path is not None:
                # Export is local staging; operator must replicate to independent custody.
                # Failure here deliberately prevents reanchoring.
                export_custody(audit_path, custody_path, secret)
                if custody_ack_path is not None:
                    mark_pending(custody_ack_path, audit_path, custody_path, secret)
        write_anchor(db_path, anchor_path, secret)
        verify_anchor(db_path, anchor_path, secret)
        return {'status': 'RECOVERED_WITH_EXTERNAL_CONFIRMATION', 'head': head,
                'cutover_authorized': False}
