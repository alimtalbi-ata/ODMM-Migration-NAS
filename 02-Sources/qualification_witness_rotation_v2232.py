"""Two-phase, fail-closed witness rotation protocol. Author: Abdelhalim Talbi.

A staged witness is not an acknowledgement. The custodian must independently
store the new record before commit; this module cannot attest remote durability.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
from qualification_custody_state_v2230 import verify_state

DOMAIN = b'ODMM-WITNESS-ROTATION-V2232\0'

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def _atomic(path, record):
    path = Path(path)
    if not path.parent.is_dir():
        raise ValueError('WITNESS_DIRECTORY_MISSING')
    tmp = path.with_name(path.name + f'.tmp.{os.getpid()}')
    try:
        with tmp.open('x') as f:
            json.dump(record, f, sort_keys=True)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        tmp.unlink(missing_ok=True)

def _load(path, secret):
    try:
        record = json.loads(Path(path).read_text())
        payload = record['payload']
        if record['schema'] != 'odmm.witness.rotation.v2232' or set(record) != {'schema','payload','mac'}:
            raise ValueError()
        expected = hmac.new(secret, DOMAIN + _canonical({'schema':record['schema'],'payload':payload}), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(record['mac'], expected):
            raise ValueError()
        return payload
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError('WITNESS_ROTATION_UNVERIFIED') from exc

def _signed(payload, secret):
    obj = {'schema':'odmm.witness.rotation.v2232','payload':payload}
    return {**obj, 'mac':hmac.new(secret, DOMAIN+_canonical(obj), hashlib.sha256).hexdigest()}

def stage_rotation(current_witness, next_witness, rotation_path, *, secret):
    """Prepare an authenticated transition; never overwrite the current witness."""
    if Path(rotation_path).exists():
        raise ValueError('WITNESS_ROTATION_ALREADY_PENDING')
    old = json.loads(Path(current_witness).read_text())
    new = json.loads(Path(next_witness).read_text())
    old_state, new_state = verify_state(old, secret), verify_state(new, secret)
    if old_state['status'] != 'CUSTODY_CONFIRMED' or new_state['status'] != 'CUSTODY_CONFIRMED':
        raise ValueError('WITNESS_NOT_CONFIRMED')
    if old == new:
        raise ValueError('WITNESS_UNCHANGED')
    if new_state['head']['current_count'] < old_state['head']['current_count']:
        raise ValueError('WITNESS_ROLLBACK')
    payload = {'phase':'PREPARED','old_sha256':hashlib.sha256(_canonical(old)).hexdigest(),
               'new_sha256':hashlib.sha256(_canonical(new)).hexdigest()}
    _atomic(rotation_path, _signed(payload, secret))
    return payload

def commit_rotation(current_witness, next_witness, rotation_path, *, secret, independent_ack_sha256):
    """Commit only after operator supplies independent custodian's exact digest.

    Digest is a comparison token, NOT a cryptographic proof of external custody.
    """
    payload = _load(rotation_path, secret)
    if payload['phase'] != 'PREPARED':
        raise ValueError('WITNESS_ROTATION_NOT_PREPARED')
    old = json.loads(Path(current_witness).read_text())
    new = json.loads(Path(next_witness).read_text())
    verify_state(old, secret); verify_state(new, secret)
    if hashlib.sha256(_canonical(old)).hexdigest() != payload['old_sha256']:
        raise ValueError('WITNESS_OLD_CHANGED')
    digest = hashlib.sha256(_canonical(new)).hexdigest()
    if digest != payload['new_sha256'] or not isinstance(independent_ack_sha256, str) or not hmac.compare_digest(digest, independent_ack_sha256):
        raise ValueError('WITNESS_ACK_MISMATCH')
    # Persist commit intent before modifying witness. If interrupted, fail closed.
    _atomic(rotation_path, _signed({**payload,'phase':'COMMITTING'}, secret))
    _atomic(current_witness, new)
    _atomic(rotation_path, _signed({**payload,'phase':'COMMITTED'}, secret))
    return {'phase':'COMMITTED','witness_sha256':digest,'cutover_authorized':False}

def rotation_status(rotation_path, *, secret):
    return _load(rotation_path, secret)['phase']

# V223.3: exclusive cross-process guard, deliberately never steals stale locks.
from contextlib import contextmanager

@contextmanager
def rotation_lock(rotation_path):
    lock = Path(str(rotation_path) + '.lock')
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ValueError('WITNESS_ROTATION_LOCKED') from exc
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(str(os.getpid()))
            stream.flush(); os.fsync(stream.fileno())
        yield
    finally:
        lock.unlink(missing_ok=True)


def stage_rotation_guarded(current_witness, next_witness, rotation_path, *, secret):
    with rotation_lock(rotation_path):
        return stage_rotation(current_witness, next_witness, rotation_path, secret=secret)


def commit_rotation_guarded(current_witness, next_witness, rotation_path, *, secret, independent_ack_sha256):
    with rotation_lock(rotation_path):
        return commit_rotation(current_witness, next_witness, rotation_path, secret=secret,
                               independent_ack_sha256=independent_ack_sha256)


def reconcile_committing(current_witness, next_witness, rotation_path, *, secret, independent_ack_sha256):
    """Explicit recovery; only finalize when committed witness bytes match staged digest.

    If old witness remains in place, refuse: a human must re-qualify the transition.
    """
    with rotation_lock(rotation_path):
        payload = _load(rotation_path, secret)
        if payload.get('phase') != 'COMMITTING':
            raise ValueError('WITNESS_NOT_COMMITTING')
        current = json.loads(Path(current_witness).read_text())
        candidate = json.loads(Path(next_witness).read_text())
        verify_state(current, secret); verify_state(candidate, secret)
        current_digest = hashlib.sha256(_canonical(current)).hexdigest()
        candidate_digest = hashlib.sha256(_canonical(candidate)).hexdigest()
        if candidate_digest != payload['new_sha256'] or current_digest != candidate_digest:
            raise ValueError('WITNESS_RECOVERY_REQUIRES_OPERATOR')
        if not isinstance(independent_ack_sha256, str) or not hmac.compare_digest(candidate_digest, independent_ack_sha256):
            raise ValueError('WITNESS_ACK_MISMATCH')
        _atomic(rotation_path, _signed({**payload, 'phase':'COMMITTED'}, secret))
        return {'phase':'COMMITTED','witness_sha256':candidate_digest,'cutover_authorized':False}
