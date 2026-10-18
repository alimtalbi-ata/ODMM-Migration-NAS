"""Fail-closed rotation gate for supervised recovery. Author: Abdelhalim Talbi.

This wrapper must be used by secure integrations; legacy direct APIs remain accessible.
The independent witness must be protected by a separate custodian.
"""
import json
from pathlib import Path
from qualification_custody_state_v2230 import verify_state
from qualification_witness_rotation_v2232 import (
    rotation_lock, stage_rotation, commit_rotation, rotation_status,
)


def _confirmed_witness(path, secret):
    try:
        record = json.loads(Path(path).read_text(encoding='utf-8'))
        state = verify_state(record, secret)
        if state['status'] != 'CUSTODY_CONFIRMED':
            raise ValueError('WITNESS_NOT_CONFIRMED')
        return record
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError('SECURE_WITNESS_UNVERIFIED') from exc


def _same_witness(path, expected, secret):
    actual = _confirmed_witness(path, secret)
    if actual != expected:
        raise ValueError('SECURE_WITNESS_DIVERGED')


def guarded_recovery_rotation(current_witness, next_witness, rotation_path, *, secret,
                              independent_current_witness, independent_ack_sha256):
    """Commit a staged rotation only with independently held current witness.

    Refuses PREPARED->COMMITTING recovery automatically; operator must use the
    separate supervised reconciliation API for any interrupted commit.
    """
    if not independent_current_witness:
        raise ValueError('INDEPENDENT_WITNESS_REQUIRED')
    with rotation_lock(rotation_path):
        baseline = _confirmed_witness(independent_current_witness, secret)
        _same_witness(current_witness, baseline, secret)
        if Path(rotation_path).exists():
            if rotation_status(rotation_path, secret=secret) != 'PREPARED':
                raise ValueError('ROTATION_REQUIRES_SUPERVISED_RECONCILIATION')
        else:
            stage_rotation(current_witness, next_witness, rotation_path, secret=secret)
        # Revalidate the independent witness before the irreversible commit.
        _same_witness(independent_current_witness, baseline, secret)
        return commit_rotation(current_witness, next_witness, rotation_path,
                               secret=secret, independent_ack_sha256=independent_ack_sha256)
