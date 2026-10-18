"""Bounded read-only registry payload gate. Author: Abdelhalim Talbi."""
from odmm_payload_gate_v2284 import validate_jobs as _previous
MAX_JOBS = 100000
MAX_ID_LENGTH = 256

def validate_jobs(rows):
    if not isinstance(rows, list):
        raise ValueError("INVALID_REGISTRY_TYPE")
    if len(rows) > MAX_JOBS:
        raise ValueError("REGISTRY_TOO_LARGE")
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("INVALID_JOB_RECORD")
        identifier = row.get("id")
        if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > MAX_ID_LENGTH:
            raise ValueError("INVALID_JOB_ID")
        if identifier != identifier.strip():
            raise ValueError("NONCANONICAL_JOB_ID")
    return _previous(rows)
