"""V192.2 read-only fail-closed recovery assessment for authenticated benchmark history.

Never truncates, repairs, or automatically authorizes an operational action.
"""
import errno
import fcntl
import os
from native_benchmark_integrity import _open, _read_locked, GENESIS
from native_benchmark_authenticated import _check


def diagnose_authenticated(path, *, keys, trusted_head=None):
    """Return sanitized cockpit state; keep original journal completely untouched."""
    base = {'schema':'odmm.benchmark.recovery.v1', 'cutover_authorized':False,
            'automatic_repair':False, 'requires_human_approval':True}
    try:
        fd = _open(path, readonly=True)
    except FileNotFoundError:
        return {**base,'status':'EMPTY','reason':'JOURNAL_ABSENT',
                'recovery':'INITIALIZE_NEW_JOURNAL_ONLY_WITH_APPROVAL'}
    except OSError:
        return {**base,'status':'BLOCKED','reason':'JOURNAL_UNREADABLE',
                'recovery':'PRESERVE_AND_ESCALATE'}
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        try:
            raw = _read_locked(fd)
            records, active, head = _check(raw, keys, trusted_head=trusted_head)
        except ValueError as exc:
            # Only classify structural incomplete-tail errors; never expose exception internals.
            reason = 'INCOMPLETE_TAIL' if str(exc) == 'INCOMPLETE_HISTORY' else 'INTEGRITY_OR_KEY_FAILURE'
            return {**base,'status':'BLOCKED','reason':reason,
                    'recovery':'PRESERVE_EVIDENCE_AND_REQUIRE_MANUAL_REVIEW'}
        if not records:
            return {**base,'status':'EMPTY','reason':'JOURNAL_EMPTY',
                    'recovery':'INITIALIZE_NEW_JOURNAL_ONLY_WITH_APPROVAL'}
        return {**base,'status':'VERIFIED','reason':'AUTHENTICATED_CHAIN_VALID',
                'records':len(records),'active_key_id':active,'head_sha256':head,
                'recovery':'NONE_REQUIRED'}
    except (OSError, TypeError, KeyError):
        return {**base,'status':'BLOCKED','reason':'JOURNAL_UNREADABLE',
                'recovery':'PRESERVE_AND_ESCALATE'}
    finally:
        os.close(fd)
