"""Independent JWKS generation witness; caller must store outside SQLite custody.
Author: Abdelhalim Talbi.
"""
import hashlib
import hmac
import json
from pathlib import Path


def witness_payload(state):
    return {'generation': state['generation'], 'jwks_sha256': state['jwks_sha256']}


def issue_witness(state, *, secret):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError('WITNESS_SECRET_INVALID')
    payload = witness_payload(state)
    message = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    return {**payload, 'mac': hmac.new(secret, message, hashlib.sha256).hexdigest()}


def verify_witness(state, *, witness_path, secret):
    try:
        witness = json.loads(Path(witness_path).read_text(encoding='utf-8'))
        expected = issue_witness(state, secret=secret)
        if set(witness) != set(expected) or any(not hmac.compare_digest(str(witness[k]), str(v)) for k, v in expected.items()):
            raise ValueError('JWKS_WITNESS_MISMATCH')
    except (OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError('JWKS_WITNESS_UNAVAILABLE') from exc
    return True


def create_witness_file(state, *, witness_path, secret):
    """Bootstrap/export only. Production requires independent authenticated custody."""
    path = Path(witness_path)
    if path.exists():
        raise ValueError('JWKS_WITNESS_EXISTS')
    with path.open('x', encoding='utf-8') as handle:
        json.dump(issue_witness(state, secret=secret), handle, sort_keys=True)
    return str(path)
