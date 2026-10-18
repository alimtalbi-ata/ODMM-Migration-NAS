"""Authenticated audit checkpoint for externally retained custody; author Abdelhalim Talbi.
The caller MUST copy checkpoint to an independent immutable store. Local paths alone
cannot prove resistance to coordinated rollback of audit and checkpoint.
"""
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from qualification_recovery_audit_v2225 import verify_recovery_audit

DOMAIN = b'ODMM-RECOVERY-CUSTODY-V2226\0'

def _payload(head):
    return json.dumps({'schema': 'odmm.recovery.custody.v2226', **head}, sort_keys=True, separators=(',', ':')).encode()

def export_custody(audit_path, custody_path, secret):
    head = verify_recovery_audit(audit_path, secret)
    payload = _payload(head)
    record = {'payload': json.loads(payload), 'mac': hmac.new(secret, DOMAIN + payload, hashlib.sha256).hexdigest()}
    target = Path(custody_path)
    if not target.parent.is_dir():
        raise ValueError('CUSTODY_DIRECTORY_MISSING')
    fd, temp = tempfile.mkstemp(prefix='.custody-', dir=target.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(record, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, target)
        dirfd = os.open(str(target.parent), os.O_RDONLY)
        try: os.fsync(dirfd)
        finally: os.close(dirfd)
    finally:
        if os.path.exists(temp): os.unlink(temp)
    return record

def verify_custody(audit_path, custody_path, secret):
    # Never accept missing independent evidence when explicitly configured.
    try:
        record = json.loads(Path(custody_path).read_text())
        if not isinstance(record, dict) or set(record) != {'payload', 'mac'}:
            raise ValueError()
        payload = record['payload']
        if not isinstance(payload, dict) or set(payload) != {'schema', 'count', 'head_mac'} or payload['schema'] != 'odmm.recovery.custody.v2226' or type(payload['count']) is not int or payload['count'] < 0:
            raise ValueError()
        encoded = _payload({'count': payload['count'], 'head_mac': payload['head_mac']})
        if not hmac.compare_digest(record['mac'], hmac.new(secret, DOMAIN + encoded, hashlib.sha256).hexdigest()):
            raise ValueError()
        current = verify_recovery_audit(audit_path, secret)
        if current['count'] < payload['count'] or (current['count'] == payload['count'] and current['head_mac'] != payload['head_mac']):
            raise ValueError()
        # For a newer audit, verify the checkpoint is an actual prefix, not just a lower count.
        if current['count'] > payload['count'] and payload['count']:
            with Path(audit_path).open('rb') as stream:
                for _ in range(payload['count']): line = stream.readline()
            if json.loads(line)['mac'] != payload['head_mac']:
                raise ValueError()
        return {'verified': True, 'checkpoint_count': payload['count'], 'current_count': current['count']}
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError('RECOVERY_CUSTODY_INTEGRITY_OR_ROLLBACK') from exc
