"""V194.2 unified fail-closed guarded rotation; gateway authenticates humans.

Legacy low-level APIs remain reachable and MUST NOT be exposed in deployed routes.
"""
import hashlib
import hmac
import json
import time
from native_benchmark_cockpit_adapter import _canonical
from native_cockpit_audit_epochs import _connect, _keys, _check, _append, _ROTATION_ADMITTED, _sealed
from native_cockpit_review_decisions import _validate as validate_review, _check_ledger
from native_rotation_target_binding import _validate as validate_target


def rotate_with_unified_governance(db, *, keys, request_id, target_key_id, signed_target,
                                   gateway_key, ledger_key, checkpoint=None, now_ns=None,
                                   trusted_review_head=None, revocation_key=None, trusted_revocation_head=None):
    """Require both signed review ledger and target-bound approval, atomically.

    trusted_review_head must be independently retained to detect review-ledger rollback.
    """
    _keys(keys)
    if not isinstance(ledger_key, bytes) or len(ledger_key) < 32:
        raise ValueError('LEDGER_KEY_INVALID')
    if not isinstance(trusted_review_head, str) or len(trusted_review_head) != 64:
        raise ValueError('EXTERNAL_REVIEW_ANCHOR_REQUIRED')
    if not isinstance(revocation_key,bytes) or len(revocation_key)<32 or not isinstance(trusted_revocation_head,str) or len(trusted_revocation_head)!=64:
        raise ValueError('EXTERNAL_REVOCATION_ANCHOR_REQUIRED')
    now_ns = time.time_ns() if now_ns is None else now_ns
    target = validate_target(signed_target, gateway_key, now_ns)
    if request_id != target['request_id'] or target_key_id != target['target_key_id']:
        raise ValueError('TARGET_APPROVAL_MISMATCH')
    if target_key_id not in keys:
        raise ValueError('TARGET_KEY_UNAVAILABLE')
    with _connect(db) as conn:
        conn.execute('BEGIN IMMEDIATE')
        state = _check(conn, keys, checkpoint)
        try:
            ledger = _check_ledger(conn, ledger_key)
        except __import__('sqlite3').OperationalError as exc:
            raise ValueError('REVIEW_LEDGER_MISSING') from exc
        if not hmac.compare_digest(ledger['head'], trusted_review_head):
            raise ValueError('REVIEW_ANCHOR_MISMATCH')
        row = conn.execute('SELECT payload_json FROM epoch_review_decisions WHERE request_id=?', (request_id,)).fetchone()
        if row is None:
            raise ValueError('REVIEW_REQUIRED')
        review = validate_review(json.loads(row[0]), gateway_key, now_ns)
        if review['decision'] != 'APPROVE':
            raise ValueError('REVIEW_DENIED')
        if any(review[k] != target[k] for k in ('request_id','requester','reviewer','expected_head')):
            raise ValueError('REVIEW_TARGET_MISMATCH')
        if not hmac.compare_digest(state['head'], target['expected_head']):
            raise ValueError('APPROVAL_STALE_HEAD')
        # Validate the independently anchored revocation chain inside the rotation transaction.
        from native_rotation_revocation_chain import _verify as verify_revocation_chain
        revocations = verify_revocation_chain(conn,revocation_key)
        if not hmac.compare_digest(revocations['head'],trusted_revocation_head):
            raise ValueError('REVOCATION_ANCHOR_MISMATCH')
        # All legacy denials must be represented in the authenticated chain;
        # otherwise even an unrelated rotation is blocked until reconciliation.
        try:
            legacy_ids = {row[0] for row in conn.execute('SELECT request_id FROM epoch_review_revocations')}
        except __import__('sqlite3').OperationalError as exc:
            raise ValueError('REVOCATION_LEDGER_MISSING') from exc
        if request_id in legacy_ids or request_id in revocations['revoked']:
            raise ValueError('REVIEW_REVOKED')
        if not legacy_ids.issubset(revocations['revoked']):
            raise ValueError('LEGACY_REVOCATIONS_NOT_RECONCILED')
        # Legacy revocations remain fail-closed and are checked too.
        try:
            revoked = conn.execute('SELECT 1 FROM epoch_review_revocations WHERE request_id=?', (request_id,)).fetchone()
        except __import__('sqlite3').OperationalError as exc:
            raise ValueError('REVOCATION_LEDGER_MISSING') from exc
        if revoked:
            raise ValueError('REVIEW_REVOKED')
        for table in ('epoch_approval_use', 'epoch_target_approvals', 'epoch_unified_approval_use'):
            try:
                used = conn.execute('SELECT 1 FROM '+table+' WHERE request_id=?',(request_id,)).fetchone()
            except __import__('sqlite3').OperationalError:
                used = None
            if used:
                raise ValueError('APPROVAL_REPLAY')
        old = state['active_key_id']
        if old is None or target_key_id == old or hmac.compare_digest(keys[old], keys[target_key_id]):
            raise ValueError('ROTATION_KEY_INVALID')
        conn.execute('CREATE TABLE IF NOT EXISTS epoch_unified_approval_use(request_id TEXT PRIMARY KEY, review_sha256 TEXT NOT NULL, target_sha256 TEXT NOT NULL, rotation_seq INTEGER NOT NULL)')
        token = _ROTATION_ADMITTED.set(True)
        try:
            result = _append(conn, keys, state, 'ROTATE', target_key_id, old)
        finally:
            _ROTATION_ADMITTED.reset(token)
        conn.execute('INSERT INTO epoch_unified_approval_use VALUES (?,?,?,?)',
                     (request_id, hashlib.sha256(row[0].encode()).hexdigest(),
                      hashlib.sha256(_canonical(signed_target)).hexdigest(), result['count']))
    return {**result,'request_id':request_id,'rotation_applied':True,'cutover_authorized':False,
            'production_qualified':False}


def rotate_with_sealed_governance(db, **kwargs):
    """Deployment entrypoint: require a pre-existing rotation seal."""
    with _connect(db) as conn:
        if not _sealed(conn):
            raise ValueError('ROTATION_SEAL_REQUIRED')
    return rotate_with_unified_governance(db, **kwargs)
