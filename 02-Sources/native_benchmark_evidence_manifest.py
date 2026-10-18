"""V192.8: HMAC authenticated, read-only forensic manifest for ODMM cockpit.

The signing key and trusted manifest digest must be held externally. This is
not an approver identity or an authorization to mutate any evidence.
"""
import hashlib
import hmac
import json
from native_benchmark_stage_inventory import cockpit_evidence_payload

SCHEMA = 'odmm.cockpit.evidence_manifest.v1'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _key(key):
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError('MANIFEST_KEY_INVALID')
    return key


def create_manifest(journal, directory, *, keys, manifest_key, key_id, trusted_head=None):
    """Capture a read-only cockpit snapshot and authenticate its canonical bytes."""
    _key(manifest_key)
    if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
        raise ValueError('MANIFEST_KEY_ID_INVALID')
    payload = cockpit_evidence_payload(journal, directory, keys=keys, trusted_head=trusted_head)
    body = {'schema': SCHEMA, 'key_id': key_id, 'payload': payload,
            'cleanup_authorized': False, 'cutover_authorized': False,
            'mutations_performed': False}
    mac = hmac.new(manifest_key, canonical(body), hashlib.sha256).hexdigest()
    return {**body, 'hmac_sha256': mac}


def verify_manifest(manifest, *, manifest_keys, trusted_manifest_sha256=None):
    """Fail closed on modified, malformed, or untrusted evidence manifests."""
    if not isinstance(manifest, dict) or set(manifest) != {
        'schema', 'key_id', 'payload', 'cleanup_authorized',
        'cutover_authorized', 'mutations_performed', 'hmac_sha256'
    }:
        raise ValueError('MANIFEST_STRUCTURE_INVALID')
    if manifest['schema'] != SCHEMA or any(manifest[field] is not False for field in (
        'cleanup_authorized', 'cutover_authorized', 'mutations_performed')):
        raise ValueError('MANIFEST_UNSAFE')
    payload = manifest['payload']
    if not isinstance(payload, dict) or payload.get('schema') != 'odmm.cockpit.evidence.v1':
        raise ValueError('MANIFEST_PAYLOAD_INVALID')
    if payload.get('cleanup_authorized') is not False or payload.get('cutover_authorized') is not False:
        raise ValueError('MANIFEST_PAYLOAD_UNSAFE')
    key_id = manifest['key_id']
    if not isinstance(key_id, str) or key_id not in manifest_keys:
        raise ValueError('MANIFEST_KEY_UNAVAILABLE')
    key = _key(manifest_keys[key_id])
    body = {k: v for k, v in manifest.items() if k != 'hmac_sha256'}
    expected = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    if not isinstance(manifest['hmac_sha256'], str) or not hmac.compare_digest(expected, manifest['hmac_sha256']):
        raise ValueError('MANIFEST_AUTHENTICATION_FAILED')
    digest = hashlib.sha256(canonical(manifest)).hexdigest()
    if trusted_manifest_sha256 is not None and not hmac.compare_digest(digest, trusted_manifest_sha256):
        raise ValueError('MANIFEST_TRUSTED_DIGEST_MISMATCH')
    return {'schema': 'odmm.cockpit.evidence_manifest_verification.v1',
            'status': 'AUTHENTICATED', 'sha256': digest,
            'evidence_status': payload.get('status'),
            'requires_human_review': payload.get('requires_human_review'),
            'cleanup_authorized': False, 'cutover_authorized': False}
