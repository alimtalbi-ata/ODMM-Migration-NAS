"""V193.9: transactional review-gated rotation, explicit signed revocation.

Caller must use this guarded API rather than legacy low-level rotation APIs.
The gateway is responsible for authenticating and authorizing humans.
"""
import hashlib
import hmac
import json
import time
from native_benchmark_cockpit_adapter import _canonical, _mac
from native_cockpit_audit_epochs import _connect, _keys, _check, _append
from native_cockpit_review_decisions import _validate, _check_ledger

REVOKE_DDL = '''CREATE TABLE IF NOT EXISTS epoch_review_revocations(
 request_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, gateway_mac TEXT NOT NULL,
 recorded_ns INTEGER NOT NULL)'''

def _guard(conn, *, keys, request_id, gateway_key, ledger_key, checkpoint, now_ns):
    state=_check(conn,keys,checkpoint)
    try:_check_ledger(conn,ledger_key)
    except __import__('sqlite3').OperationalError as exc:raise ValueError('REVIEW_REQUIRED') from exc
    row=conn.execute('SELECT payload_json FROM epoch_review_decisions WHERE request_id=?',(request_id,)).fetchone()
    if row is None:raise ValueError('REVIEW_REQUIRED')
    signed=json.loads(row[0]); p=_validate(signed,gateway_key,now_ns)
    if p['decision']!='APPROVE':raise ValueError('REVIEW_DENIED')
    if p['expected_head']!=state['head']:raise ValueError('REVIEW_STALE_HEAD')
    if conn.execute('SELECT 1 FROM epoch_review_revocations WHERE request_id=?',(request_id,)).fetchone():
        raise ValueError('REVIEW_REVOKED')
    return state,p

def revoke_review(db, *, keys, signed_deny, gateway_key, ledger_key, checkpoint=None, now_ns=None):
    """Revokes an existing approval; deny must match original request and head.

    Revocation is immutable and fails closed if the underlying audit changes.
    """
    _keys(keys)
    if not isinstance(ledger_key,bytes) or len(ledger_key)<32:raise ValueError('REVIEW_LEDGER_KEY_INVALID')
    now_ns=time.time_ns() if now_ns is None else now_ns
    deny=_validate(signed_deny,gateway_key,now_ns)
    if deny['decision']!='DENY':raise ValueError('REVOKE_DENY_REQUIRED')
    with _connect(db) as conn:
        conn.execute('BEGIN IMMEDIATE')
        _check(conn,keys,checkpoint)
        try:_check_ledger(conn,ledger_key)
        except __import__('sqlite3').OperationalError as exc:raise ValueError('REVOKE_UNKNOWN_REQUEST') from exc
        conn.execute(REVOKE_DDL)
        row=conn.execute('SELECT payload_json FROM epoch_review_decisions WHERE request_id=?',(deny['request_id'],)).fetchone()
        if row is None:raise ValueError('REVOKE_UNKNOWN_REQUEST')
        original=json.loads(row[0])['payload']
        if original['decision']!='APPROVE' or any(deny[k]!=original[k] for k in ('request_id','requester','expected_head')):
            raise ValueError('REVOKE_CONTEXT_MISMATCH')
        conn.execute('CREATE TABLE IF NOT EXISTS epoch_approval_use(request_id TEXT PRIMARY KEY, reviewer TEXT NOT NULL, approval_sha256 TEXT NOT NULL, rotation_seq INTEGER NOT NULL)')
        if conn.execute('SELECT 1 FROM epoch_approval_use WHERE request_id=?',(deny['request_id'],)).fetchone():
            raise ValueError('REVOKE_ALREADY_USED')
        conn.execute('INSERT INTO epoch_review_revocations VALUES (?,?,?,?)',
                     (deny['request_id'],_canonical(deny).decode(),signed_deny['gateway_mac'],now_ns))
    return {'revoked':True,'request_id':deny['request_id'],'rotation_applied':False,'cutover_authorized':False}

def apply_review_gated_rotation(db, *, keys, request_id, new_key_id, gateway_key, ledger_key,
                                checkpoint=None, now_ns=None):
    """Checks review, revocation, epoch head and replay in one IMMEDIATE transaction."""
    _keys(keys)
    if not isinstance(ledger_key,bytes) or len(ledger_key)<32:raise ValueError('REVIEW_LEDGER_KEY_INVALID')
    if not isinstance(request_id,str) or not request_id or new_key_id not in keys:raise ValueError('ROTATION_REQUEST_INVALID')
    now_ns=time.time_ns() if now_ns is None else now_ns
    with _connect(db) as conn:
        conn.execute('BEGIN IMMEDIATE')
        # Do not bootstrap a missing review ledger or epoch journal.
        conn.execute(REVOKE_DDL)
        state,p=_guard(conn,keys=keys,request_id=request_id,gateway_key=gateway_key,
                       ledger_key=ledger_key,checkpoint=checkpoint,now_ns=now_ns)
        old=state['active_key_id']
        if not old or new_key_id==old or hmac.compare_digest(keys[old],keys[new_key_id]):
            raise ValueError('ROTATION_KEY_INVALID')
        conn.execute('CREATE TABLE IF NOT EXISTS epoch_approval_use(request_id TEXT PRIMARY KEY, reviewer TEXT NOT NULL, approval_sha256 TEXT NOT NULL, rotation_seq INTEGER NOT NULL)')
        if conn.execute('SELECT 1 FROM epoch_approval_use WHERE request_id=?',(request_id,)).fetchone():
            raise ValueError('ROTATION_REPLAY')
        result=_append(conn,keys,state,'ROTATE',new_key_id,old)
        conn.execute('CREATE TABLE IF NOT EXISTS epoch_approval_use(request_id TEXT PRIMARY KEY, reviewer TEXT NOT NULL, approval_sha256 TEXT NOT NULL, rotation_seq INTEGER NOT NULL)')
        conn.execute('INSERT INTO epoch_approval_use VALUES (?,?,?,?)',
                     (request_id,p['reviewer'],hashlib.sha256(_canonical(p)).hexdigest(),result['count']))
    return {**result,'review_request_id':request_id,'rotation_applied':True,'cutover_authorized':False}
