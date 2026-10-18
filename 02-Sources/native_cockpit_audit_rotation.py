"""V193.5: signed, read-only audit key rotation handoff.

This is a proposal, not a live key switch. Old audit rows remain verified with
old key; a new epoch requires a separately deployed epoch-aware writer.
"""
import hashlib
import hmac
import re
from native_benchmark_cockpit_adapter import _canonical
from native_cockpit_audit_operations import verify_access_audit_prefix, verify_access_audit

_KEY_ID = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')


def _key(value):
    if not isinstance(value, bytes) or len(value) < 32:
        raise ValueError('ROTATION_KEY_INVALID')
    return value


def prepare_rotation(db_path, *, old_key, new_key, old_key_id, new_key_id,
                     checkpoint_count, checkpoint_head, request_id):
    """Attest current audit chain and bind a proposed new key to its checkpoint."""
    _key(old_key)
    _key(new_key)
    if not all(isinstance(v, str) and _KEY_ID.fullmatch(v) for v in (old_key_id, new_key_id)):
        raise ValueError('ROTATION_KEY_ID_INVALID')
    if old_key_id == new_key_id or hmac.compare_digest(old_key, new_key):
        raise ValueError('ROTATION_REUSED_KEY')
    if not isinstance(request_id, str) or not (8 <= len(request_id) <= 128):
        raise ValueError('ROTATION_REQUEST_INVALID')
    state = verify_access_audit_prefix(db_path, audit_key=old_key,
                                      checkpoint_count=checkpoint_count,
                                      checkpoint_head=checkpoint_head)
    payload = {'schema': 'odmm.cockpit.audit.rotation.proposal.v1',
               'old_key_id': old_key_id, 'new_key_id': new_key_id,
               'checkpoint_count': checkpoint_count, 'checkpoint_head': checkpoint_head,
               'current_count': state['count'], 'current_head': state['head_sha256'],
               'request_id': request_id, 'status': 'PENDING_APPROVAL',
               'rotation_applied': False, 'cutover_authorized': False}
    return {'payload': payload,
            'old_key_mac': hmac.new(old_key, _canonical(payload), hashlib.sha256).hexdigest(),
            'new_key_mac': hmac.new(new_key, _canonical(payload), hashlib.sha256).hexdigest()}


def verify_rotation(proposal, *, old_key, new_key, expected_request_id,
                    expected_current_head=None):
    _key(old_key)
    _key(new_key)
    if not isinstance(proposal, dict) or set(proposal) != {'payload', 'old_key_mac', 'new_key_mac'}:
        raise ValueError('ROTATION_FORMAT_INVALID')
    p = proposal['payload']
    if not isinstance(p, dict) or set(p) != {'schema','old_key_id','new_key_id','checkpoint_count',
                                           'checkpoint_head','current_count','current_head',
                                           'request_id','status','rotation_applied','cutover_authorized'}:
        raise ValueError('ROTATION_FORMAT_INVALID')
    if (p['schema'] != 'odmm.cockpit.audit.rotation.proposal.v1' or
        p['request_id'] != expected_request_id or p['status'] != 'PENDING_APPROVAL' or
        p['rotation_applied'] is not False or p['cutover_authorized'] is not False):
        raise ValueError('ROTATION_CONTEXT_INVALID')
    if expected_current_head is not None and p['current_head'] != expected_current_head:
        raise ValueError('ROTATION_HEAD_MISMATCH')
    for field, key in (('old_key_mac',old_key),('new_key_mac',new_key)):
        mac = proposal[field]
        if not isinstance(mac,str) or not hmac.compare_digest(mac, hmac.new(key,_canonical(p),hashlib.sha256).hexdigest()):
            raise ValueError('ROTATION_MAC_INVALID')
    return {'status':'VERIFIED_PENDING_APPROVAL','rotation_applied':False,
            'cutover_authorized':False,'current_head':p['current_head']}
