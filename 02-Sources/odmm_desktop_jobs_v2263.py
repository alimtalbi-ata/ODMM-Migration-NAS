"""Untrusted, offline job-status report viewer. Never contacts or commands the engine."""
import json
from pathlib import Path

MAX_BYTES = 4 * 1024 * 1024
STATES = frozenset({'CREATED','PENDING','QUEUED','RUNNING','PAUSED','VERIFYING','COMPLETED','FAILED','BLOCKED','CANCELLED','UNKNOWN'})

def load_job_status(path):
    path = Path(path)
    with path.open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('REPORT_TOO_LARGE')
    try:
        data = json.loads(raw.decode('utf-8'))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('INVALID_JOB_REPORT') from exc
    if not isinstance(data, dict):
        raise ValueError('INVALID_JOB_REPORT')
    jobs = data.get('jobs')
    if not isinstance(jobs, list) or len(jobs) > 10000:
        raise ValueError('INVALID_JOBS')
    output = []
    for job in jobs:
        if not isinstance(job, dict):
            raise ValueError('INVALID_JOB')
        jid, state = job.get('id'), job.get('status')
        if not isinstance(jid, str) or not (1 <= len(jid) <= 128) or any(ord(c) < 32 for c in jid):
            raise ValueError('INVALID_JOB_ID')
        if not isinstance(state, str):
            raise ValueError('INVALID_JOB_STATE')
        normalized = state.upper()
        if normalized not in STATES:
            normalized = 'UNKNOWN'
        output.append({'id': jid, 'status': normalized, 'source_status': state[:128]})
    return output
