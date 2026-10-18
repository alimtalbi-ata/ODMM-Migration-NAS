"""Authenticated custody acknowledgement state. Author: Abdelhalim Talbi.

An HMAC protects local modification, NOT rollback if state and witness are both replaced.
"""
import hashlib
import hmac
import json
from pathlib import Path

DOMAIN = b'ODMM-CUSTODY-ACK-V2230\0'


def _bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')


def seal_state(payload, secret):
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
        raise ValueError('CUSTODY_ACK_SECRET_INVALID')
    if (not isinstance(payload, dict) or set(payload) != {'status', 'head'} or
        payload['status'] not in ('PENDING_CUSTODY_ACK', 'CUSTODY_CONFIRMED') or
        not isinstance(payload['head'], dict) or
        set(payload['head']) != {'verified', 'checkpoint_count', 'current_count'} or
        payload['head'].get('verified') is not True or
        any(type(payload['head'].get(k)) is not int or payload['head'][k] < 0 for k in ('checkpoint_count', 'current_count')) or
        payload['head']['checkpoint_count'] > payload['head']['current_count']):
        raise ValueError('CUSTODY_ACK_PAYLOAD_INVALID')
    data = {'schema': 'odmm.custody.ack.v2230', 'payload': json.loads(_bytes(payload))}
    return {**data, 'mac': hmac.new(secret, DOMAIN + _bytes(data), hashlib.sha256).hexdigest()}


def verify_state(record, secret):
    try:
        if not isinstance(record, dict) or set(record) != {'schema', 'payload', 'mac'} or record['schema'] != 'odmm.custody.ack.v2230':
            raise ValueError()
        expected = seal_state(record['payload'], secret)
        if not isinstance(record['mac'], str) or not hmac.compare_digest(record['mac'], expected['mac']):
            raise ValueError()
        return record['payload']
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError('CUSTODY_ACK_STATE_UNVERIFIED') from exc


def verify_witness(state, witness_path, secret):
    """Optional separately retained exact witness; caller must protect independent storage."""
    try:
        witness = json.loads(Path(witness_path).read_text(encoding='utf-8'))
        verified = verify_state(witness, secret)
        if verified != state:
            raise ValueError()
        return True
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError('CUSTODY_ACK_WITNESS_MISMATCH') from exc
