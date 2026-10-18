"""V188.6: independently keyed two-host technical attestations and replay registry.

A signature proves possession of a host key, not physical host independence or
actual execution of the described operation. No remote actions or cutover.
"""
import hashlib
import hmac
import json
import sqlite3
import time
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_two_host_runbook import canonical, signed_report, verify_report

HOSTS = ('source', 'witness')
SAFE = ('cutover_authorized', 'recovery_authorized', 'publication_authorized')

def attestation(*, host, run_id, incident_id, scenario, observation, timestamp, nonce):
    if host not in HOSTS or not all(isinstance(x, str) and x.strip() for x in
        (run_id, incident_id, scenario, observation, nonce)):
        raise IdentityPinError('ATTESTATION_FIELDS_INVALID')
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
        raise IdentityPinError('ATTESTATION_TIME_INVALID')
    if len(nonce) < 32 or len(run_id) < 12:
        raise IdentityPinError('ATTESTATION_ID_WEAK')
    return {'schema': 2, 'host': host, 'run_id': run_id, 'incident_id': incident_id,
            'scenario': scenario, 'observation': observation, 'timestamp': timestamp,
            'nonce': nonce, 'technical_execution_independently_proven': False,
            **{flag: False for flag in SAFE}}

def verify_pair(envelopes, *, keys, run_id, incident_id, scenario, now=None, max_age=3600):
    if not isinstance(envelopes, (tuple, list)) or len(envelopes) != 2:
        raise IdentityPinError('TWO_HOST_EVIDENCE_REQUIRED')
    if not isinstance(keys, dict) or set(keys) != set(HOSTS) or keys['source'] == keys['witness']:
        raise IdentityPinError('INDEPENDENT_KEYS_REQUIRED')
    now = int(time.time()) if now is None else now
    if not isinstance(now, int) or not isinstance(max_age, int) or max_age < 1:
        raise IdentityPinError('CLOCK_INVALID')
    verified = {}
    for env in envelopes:
        if not isinstance(env, dict) or not isinstance(env.get('report'), dict):
            raise IdentityPinError('ATTESTATION_FORMAT_INVALID')
        host = env['report'].get('host')
        if host not in HOSTS or host in verified:
            raise IdentityPinError('HOST_DUPLICATE_OR_UNKNOWN')
        record = verify_report(env, key=keys[host])
        if set(record) != {'schema', 'host', 'run_id', 'incident_id', 'scenario',
                           'observation', 'timestamp', 'nonce',
                           'technical_execution_independently_proven', *SAFE}:
            raise IdentityPinError('ATTESTATION_SCHEMA_INVALID')
        if record != attestation(host=host, run_id=record['run_id'],
            incident_id=record['incident_id'], scenario=record['scenario'],
            observation=record['observation'], timestamp=record['timestamp'], nonce=record['nonce']):
            raise IdentityPinError('ATTESTATION_UNSAFE')
        if (record['run_id'], record['incident_id'], record['scenario']) != (run_id, incident_id, scenario):
            raise IdentityPinError('ATTESTATION_CONTEXT_MISMATCH')
        if not 0 <= now - record['timestamp'] <= max_age:
            raise IdentityPinError('ATTESTATION_EXPIRED_OR_FUTURE')
        verified[host] = record
    if set(verified) != set(HOSTS) or verified['source']['nonce'] == verified['witness']['nonce']:
        raise IdentityPinError('TWO_HOST_DISTINCTNESS_INVALID')
    return {'schema': 2, 'run_id': run_id, 'incident_id': incident_id,
            'scenario': scenario, 'host_evidence': [verified[h] for h in HOSTS],
            'status': 'TWO_HOST_SIGNED_STATEMENTS_REVIEW_REQUIRED',
            'technical_execution_independently_proven': False,
            'remote_independence_proven': False, 'manual_review_required': True,
            **{flag: False for flag in SAFE}}

class ReplayRegistry:
    """Durable SQLite UNIQUE constraints: atomic replay protection across processes."""
    def __init__(self, path):
        self.path = Path(path)
    def register(self, report):
        if report.get('status') != 'TWO_HOST_SIGNED_STATEMENTS_REVIEW_REQUIRED' or any(report.get(f) is not False for f in SAFE):
            raise IdentityPinError('REGISTRY_REPORT_UNSAFE')
        evidence = report.get('host_evidence')
        if not isinstance(evidence, list) or len(evidence) != 2:
            raise IdentityPinError('REGISTRY_EVIDENCE_INVALID')
        with sqlite3.connect(self.path, timeout=3) as db:
            db.execute('CREATE TABLE IF NOT EXISTS seen (host TEXT NOT NULL, nonce TEXT NOT NULL, run_id TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(host, nonce), UNIQUE(host, run_id))')
            try:
                db.execute('BEGIN IMMEDIATE')
                for item in evidence:
                    db.execute('INSERT INTO seen VALUES (?,?,?,?)', (item['host'], item['nonce'], item['run_id'], hashlib.sha256(canonical(item)).hexdigest()))
                db.commit()
            except sqlite3.IntegrityError as exc:
                db.rollback()
                raise IdentityPinError('EVIDENCE_REPLAY_DETECTED') from exc
        return {'status': 'EVIDENCE_REGISTERED_REVIEW_REQUIRED', 'run_id': report['run_id'],
                'manual_review_required': True, **{flag: False for flag in SAFE}}
