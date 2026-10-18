"""ODMM V202.7 — local read-only probe and HMAC evidence envelope.
Author: Abdelhalim Talbi. HMAC proves possession of shared key, not remote NAS identity.
"""
import hashlib
import hmac
import json
import os
import re
import time
from readonly_access_probe import probe_readonly

SCHEMA = 'odmm.access.attestation.v2027'
_SAFE = re.compile(r'^[A-Za-z0-9_.@-]{1,128}$')

def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def collect(root, relative_path, *, expected_euid, key, key_id, campaign_id, expected_egid=None):
    """Run under the explicitly expected local process identity; no impersonation."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError('WEAK_OR_MISSING_HMAC_KEY')
    if not all(isinstance(x, str) and _SAFE.fullmatch(x) for x in (key_id, campaign_id)):
        raise ValueError('INVALID_KEY_OR_CAMPAIGN_ID')
    if not isinstance(relative_path, str) or not relative_path or relative_path.startswith('/') or '\\' in relative_path or '\x00' in relative_path or any(p in ('', '.', '..') for p in relative_path.split('/')):
        raise ValueError('UNSAFE_RELATIVE_PATH')
    result = probe_readonly(root, relative_path, expected_euid=expected_euid, expected_egid=expected_egid)
    decision = {'OPEN_READ_SUCCEEDED': 'ALLOW', 'OPEN_READ_DENIED': 'DENY'}.get(result['report']['outcome'])
    if decision is None:
        raise ValueError('UNRECOGNIZED_PROBE_OUTCOME')
    payload = {'schema': SCHEMA, 'author': 'Abdelhalim Talbi', 'campaign_id': campaign_id,
               'key_id': key_id, 'timestamp_ns': time.time_ns(), 'path': relative_path,
               'principal': 'UID:' + str(expected_euid), 'action': 'READ_DATA', 'decision': decision,
               'method': 'INDEPENDENT_READ_ONLY_PROBE', 'probe_sha256': result['sha256'],
               'probe_report': result['report'], 'identity_impersonation': False,
               'remote_nas_identity_verified': False, 'cutover_authorized': False,
               'writes_to_nas': False, 'native_engine_default': True,
               'silent_fallback_allowed': False}
    signature = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    return {'payload': payload, 'signature_algorithm': 'HMAC-SHA256', 'signature': signature}

def verify(envelope, *, key, expected_key_id, expected_campaign_id, max_age_seconds=3600, now_ns=None):
    """Reject invalid signatures, wrong campaign, stale/future timestamps, unsafe fields."""
    if not isinstance(key, bytes) or len(key) < 32 or type(max_age_seconds) not in (int, float) or not 0 < max_age_seconds <= 86400:
        return False
    try:
        if not isinstance(envelope, dict) or set(envelope) != {'payload', 'signature_algorithm', 'signature'}:
            return False
        p = envelope['payload']
        if not isinstance(p, dict) or p.get('schema') != SCHEMA or p.get('key_id') != expected_key_id or p.get('campaign_id') != expected_campaign_id:
            return False
        if p.get('action') != 'READ_DATA' or p.get('decision') not in ('ALLOW', 'DENY') or p.get('method') != 'INDEPENDENT_READ_ONLY_PROBE':
            return False
        if p.get('cutover_authorized') is not False or p.get('writes_to_nas') is not False or p.get('native_engine_default') is not True or p.get('silent_fallback_allowed') is not False or p.get('remote_nas_identity_verified') is not False:
            return False
        if type(p.get('timestamp_ns')) is not int:
            return False
        current = time.time_ns() if now_ns is None else now_ns
        if type(current) is not int or p['timestamp_ns'] > current + 5_000_000_000 or current - p['timestamp_ns'] > max_age_seconds * 1_000_000_000:
            return False
        if envelope['signature_algorithm'] != 'HMAC-SHA256' or not isinstance(envelope['signature'], str) or not re.fullmatch('[0-9a-f]{64}', envelope['signature']):
            return False
        if not hmac.compare_digest(hmac.new(key, _canonical(p), hashlib.sha256).hexdigest(), envelope['signature']):
            return False
        report = p.get('probe_report')
        if not isinstance(report, dict) or report.get('execution_euid') is None or p.get('principal') != 'UID:' + str(report['execution_euid']):
            return False
        if p['decision'] != {'OPEN_READ_SUCCEEDED': 'ALLOW', 'OPEN_READ_DENIED': 'DENY'}.get(report.get('outcome')):
            return False
        return hmac.compare_digest(hashlib.sha256(_canonical(report)).hexdigest(), p['probe_sha256'])
    except (TypeError, ValueError, KeyError, OverflowError):
        return False

def as_comparison_record(envelope, *, key, expected_key_id, expected_campaign_id):
    if not verify(envelope, key=key, expected_key_id=expected_key_id, expected_campaign_id=expected_campaign_id):
        raise ValueError('UNVERIFIED_ATTESTATION')
    p = envelope['payload']
    return {'path': p['path'], 'principal': p['principal'], 'action': p['action'],
            'decision': p['decision'], 'method': p['method'],
            'evidence_id': hashlib.sha256(_canonical(envelope)).hexdigest()}
