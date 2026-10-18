"""Authenticated, append-only recovery evidence (not independent immutable custody).
Author: Abdelhalim Talbi.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _mac(secret, event):
    return hmac.new(secret, b'ODMM-RECOVERY-AUDIT-V2225\0' + _canonical(event), hashlib.sha256).hexdigest()


def verify_recovery_audit(path, secret):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError('INVALID_AUDIT_KEY')
    previous = 'GENESIS'
    count = 0
    p = Path(path)
    if not p.exists():
        return {'count': 0, 'head_mac': previous}
    with p.open('rb') as stream:
        for line in stream:
            try:
                row = json.loads(line)
                event = row['event']
                if (set(row) != {'event', 'mac'} or not isinstance(event, dict)
                        or event['seq'] != count + 1 or event['previous_mac'] != previous
                        or not hmac.compare_digest(row['mac'], _mac(secret, event))):
                    raise ValueError('RECOVERY_AUDIT_INTEGRITY_FAILURE')
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError('RECOVERY_AUDIT_INTEGRITY_FAILURE') from exc
            previous = row['mac']
            count += 1
    return {'count': count, 'head_mac': previous}


def append_recovery_audit(path, secret, *, operator, confirmed_head):
    if not isinstance(operator, str) or not operator.strip() or len(operator) > 128:
        raise ValueError('RECOVERY_OPERATOR_REQUIRED')
    if not isinstance(confirmed_head, dict) or set(confirmed_head) != {'schema', 'count', 'head_mac'}:
        raise ValueError('INVALID_CONFIRMED_HEAD')
    p = Path(path)
    if not p.parent.is_dir():
        raise ValueError('AUDIT_DIRECTORY_MISSING')
    head = verify_recovery_audit(path, secret)
    event = {'seq': head['count'] + 1, 'previous_mac': head['head_mac'],
             'operator': operator.strip(), 'confirmed_head': confirmed_head,
             'operation': 'SUPERVISED_ANCHOR_RECOVERY', 'cutover_authorized': False}
    row = _canonical({'event': event, 'mac': _mac(secret, event)}) + b'\n'
    fd = os.open(str(p), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        with os.fdopen(fd, 'ab') as out:
            out.write(row)
            out.flush()
            os.fsync(out.fileno())
    finally:
        pass
    return verify_recovery_audit(path, secret)
