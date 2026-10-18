"""Fail-closed external custody acknowledgement lifecycle. Author: Abdelhalim Talbi.

A local state file is only a gate; independent custody remains the operator's duty.
"""
import json
import os
from pathlib import Path
from qualification_external_receipt_v2228 import verify_external_receipt
from qualification_recovery_custody_v2226 import verify_custody
from qualification_custody_state_v2230 import seal_state, verify_state, verify_witness


def _atomic(path, value):
    path = Path(path)
    if not path.parent.is_dir():
        raise ValueError('CUSTODY_STATE_DIRECTORY_MISSING')
    tmp = path.with_name(path.name + '.tmp.' + str(os.getpid()))
    try:
        with tmp.open('x', encoding='utf-8') as f:
            json.dump(value, f, sort_keys=True)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
        directory = os.open(str(path.parent), os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        tmp.unlink(missing_ok=True)


def read_ack_state(path, *, secret=None, witness_path=None):
    try:
        record = json.loads(Path(path).read_text(encoding='utf-8'))
        if secret is not None:
            state = verify_state(record, secret)
            if witness_path is not None:
                verify_witness(state, witness_path, secret)
            return state
        # Legacy read-only inspection: never use unauthenticated mode for a security gate.
        if isinstance(record, dict) and record.get('schema') == 'odmm.custody.ack.v2230':
            raise ValueError('CUSTODY_ACK_SECRET_REQUIRED')
        if (not isinstance(record, dict) or set(record) != {'status', 'head'} or
                record.get('status') not in ('PENDING_CUSTODY_ACK', 'CUSTODY_CONFIRMED') or
                not isinstance(record.get('head'), dict)):
            raise ValueError()
        return record
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError('CUSTODY_ACK_STATE_UNVERIFIED') from exc


def mark_pending(state_path, audit_path, custody_path, secret):
    head = verify_custody(audit_path, custody_path, secret)
    state = {'status': 'PENDING_CUSTODY_ACK', 'head': head}
    _atomic(state_path, seal_state(state, secret))
    return state


def confirm_custody(state_path, audit_path, custody_path, receipt_path, *, secret, custodian_key, custodian, secure_custody=False, witness_path=None):
    if secure_custody and witness_path is None:
        raise ValueError('SECURE_CUSTODY_WITNESS_REQUIRED')
    state = read_ack_state(state_path, secret=secret,
                           witness_path=witness_path if secure_custody else None)
    if state['status'] != 'PENDING_CUSTODY_ACK':
        raise ValueError('CUSTODY_NOT_PENDING')
    head = verify_custody(audit_path, custody_path, secret)
    if head != state['head']:
        raise ValueError('CUSTODY_HEAD_CHANGED')
    result = verify_external_receipt(audit_path, custody_path, receipt_path,
                                     secret=secret, custodian_key=custodian_key, custodian=custodian)
    _atomic(state_path, seal_state({'status': 'CUSTODY_CONFIRMED', 'head': head}, secret))
    return {'status': 'CUSTODY_CONFIRMED', 'receipt': result, 'cutover_authorized': False}
