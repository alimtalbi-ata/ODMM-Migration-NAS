"""V188.5: fail-closed, read-only aggregation of independently signed qualification evidence.

No service operations, migration, witness publication, recovery or cutover.
"""
import hashlib
import json
import time
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_two_host_runbook import canonical, signed_report, verify_report, write_report

SCENARIOS = ('baseline', 'network_partition', 'network_recovery', 'systemd_restart', 'backup_restore')
VALID_OUTCOMES = {'PASS', 'FAIL', 'NOT_EXECUTED'}


def scenario_evidence(*, incident_id, scenario, outcome, operator, observations, timestamp=None):
    if not isinstance(incident_id, str) or not incident_id.strip():
        raise IdentityPinError('INCIDENT_REQUIRED')
    if scenario not in SCENARIOS or outcome not in VALID_OUTCOMES:
        raise IdentityPinError('SCENARIO_INVALID')
    if not isinstance(operator, str) or not operator.strip():
        raise IdentityPinError('OPERATOR_REQUIRED')
    if not isinstance(observations, str) or not observations.strip():
        raise IdentityPinError('OBSERVATIONS_REQUIRED')
    if timestamp is None: timestamp = int(time.time())
    if not isinstance(timestamp, int) or timestamp < 0:
        raise IdentityPinError('TIMESTAMP_INVALID')
    return {'schema': 1, 'incident_id': incident_id, 'scenario': scenario,
            'outcome': outcome, 'operator': operator, 'observations': observations,
            'timestamp': timestamp, 'cutover_authorized': False,
            'recovery_authorized': False, 'publication_authorized': False}


def consolidate(envelopes, *, key, incident_id):
    if not isinstance(envelopes, (list, tuple)) or not envelopes:
        raise IdentityPinError('EVIDENCE_REQUIRED')
    evidence = {}
    for envelope in envelopes:
        record = verify_report(envelope, key=key)
        if not isinstance(record, dict) or record.get('schema') != 1:
            raise IdentityPinError('EVIDENCE_SCHEMA_INVALID')
        scenario = record.get('scenario')
        if scenario not in SCENARIOS or record.get('outcome') not in VALID_OUTCOMES:
            raise IdentityPinError('EVIDENCE_SCENARIO_INVALID')
        if record.get('incident_id') != incident_id:
            raise IdentityPinError('EVIDENCE_INCIDENT_MISMATCH')
        if any(record.get(flag) is not False for flag in
               ('cutover_authorized', 'recovery_authorized', 'publication_authorized')):
            raise IdentityPinError('EVIDENCE_UNSAFE')
        if scenario in evidence:
            raise IdentityPinError('DUPLICATE_SCENARIO')
        if not isinstance(record.get('timestamp'), int) or record['timestamp'] < 0:
            raise IdentityPinError('EVIDENCE_TIMESTAMP_INVALID')
        if not isinstance(record.get('operator'), str) or not record['operator'].strip():
            raise IdentityPinError('EVIDENCE_OPERATOR_INVALID')
        if not isinstance(record.get('observations'), str) or not record['observations'].strip():
            raise IdentityPinError('EVIDENCE_OBSERVATIONS_INVALID')
        evidence[scenario] = record
    outcomes = {scenario: evidence[scenario]['outcome'] if scenario in evidence
                else 'MISSING' for scenario in SCENARIOS}
    # A report is evidence of the collected statements, NOT independent proof of execution.
    status = ('REPORTED_COMPLETE' if all(v == 'PASS' for v in outcomes.values())
              else 'REVIEW_REQUIRED')
    return {'schema': 1, 'incident_id': incident_id, 'status': status,
            'scenario_outcomes': outcomes, 'evidence': [evidence[s] for s in SCENARIOS if s in evidence],
            'evidence_count': len(evidence), 'remote_independence_proven': False,
            'manual_review_required': True, 'cutover_authorized': False,
            'recovery_authorized': False, 'publication_authorized': False}


def collect_files(paths, *, key, incident_id, output):
    if not paths:
        raise IdentityPinError('EVIDENCE_REQUIRED')
    documents = []
    for path in paths:
        p = Path(path)
        if p.is_symlink() or not p.is_file():
            raise IdentityPinError('EVIDENCE_FILE_UNSAFE')
        if p.stat().st_size > 1024 * 1024:
            raise IdentityPinError('EVIDENCE_FILE_TOO_LARGE')
        try:
            documents.append(json.loads(p.read_text(encoding='utf-8')))
        except (ValueError, UnicodeError) as exc:
            raise IdentityPinError('EVIDENCE_FILE_INVALID') from exc
    report = consolidate(documents, key=key, incident_id=incident_id)
    return write_report(output, signed_report(report, key=key))
