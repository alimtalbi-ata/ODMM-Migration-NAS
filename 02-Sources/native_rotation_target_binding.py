"""V194.1: target-bound approval for the guarded epoch rotation endpoint.

The gateway authenticates humans before signing; this module never trusts headers.
The existing v1 API remains for compatibility and is NOT production-qualified.
"""
import hashlib
import hmac
import re
import time
from native_benchmark_cockpit_adapter import _canonical, _mac
from native_cockpit_audit_epochs import _connect, _keys, _check, _append
from native_cockpit_review_decisions import IDENT, HEX

KEY_ID = re.compile(r'[A-Za-z0-9_.-]{1,64}\Z')
DDL = '''CREATE TABLE IF NOT EXISTS epoch_target_approvals(
 request_id TEXT PRIMARY KEY, signed_json TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0,
 rotation_seq INTEGER, CHECK(used IN (0,1)))'''

def sign_target_approval(*, gateway_key, request_id, requester, reviewer, target_key_id,
                         expected_head, issued_ns, expires_ns):
    if not isinstance(gateway_key,bytes) or len(gateway_key)<32:raise ValueError('GATEWAY_KEY_INVALID')
    if any(not isinstance(v,str) or not IDENT.fullmatch(v) for v in (request_id,requester,reviewer)) or requester==reviewer:
        raise ValueError('APPROVAL_IDENTITY_INVALID')
    if not isinstance(target_key_id,str) or not KEY_ID.fullmatch(target_key_id):raise ValueError('TARGET_KEY_INVALID')
    if not isinstance(expected_head,str) or not HEX.fullmatch(expected_head):raise ValueError('EXPECTED_HEAD_INVALID')
    if type(issued_ns) is not int or type(expires_ns) is not int or expires_ns<=issued_ns:raise ValueError('APPROVAL_TIME_INVALID')
    p={'schema':'odmm.rotation.target_approval.v2','request_id':request_id,'requester':requester,
       'reviewer':reviewer,'target_key_id':target_key_id,'expected_head':expected_head,
       'issued_ns':issued_ns,'expires_ns':expires_ns,'cutover_authorized':False}
    return {'payload':p,'gateway_mac':_mac(gateway_key,p)}

def _validate(signed, gateway_key, now_ns):
    if not isinstance(signed,dict) or set(signed)!={'payload','gateway_mac'} or not isinstance(signed['payload'],dict):raise ValueError('APPROVAL_INVALID')
    p=signed['payload']
    if set(p)!={'schema','request_id','requester','reviewer','target_key_id','expected_head','issued_ns','expires_ns','cutover_authorized'}:raise ValueError('APPROVAL_INVALID')
    if p['schema']!='odmm.rotation.target_approval.v2' or p['cutover_authorized'] is not False:raise ValueError('APPROVAL_INVALID')
    if not isinstance(gateway_key,bytes) or len(gateway_key)<32 or not isinstance(signed['gateway_mac'],str) or not hmac.compare_digest(signed['gateway_mac'],_mac(gateway_key,p)):
        raise ValueError('APPROVAL_MAC_INVALID')
    if any(not isinstance(p[k],str) or not IDENT.fullmatch(p[k]) for k in ('request_id','requester','reviewer')) or p['requester']==p['reviewer']:
        raise ValueError('APPROVAL_IDENTITY_INVALID')
    if not isinstance(p['target_key_id'],str) or not KEY_ID.fullmatch(p['target_key_id']) or not isinstance(p['expected_head'],str) or not HEX.fullmatch(p['expected_head']):raise ValueError('APPROVAL_CONTEXT_INVALID')
    if type(now_ns) is not int or type(p['issued_ns']) is not int or type(p['expires_ns']) is not int or not p['issued_ns']<=now_ns<p['expires_ns']:
        raise ValueError('APPROVAL_EXPIRED')
    return p

def apply_target_bound_rotation(db, *, keys, signed, gateway_key, checkpoint=None, now_ns=None):
    """Atomically verify target, audit head and one-use approval before ROTATE."""
    _keys(keys)
    now_ns=time.time_ns() if now_ns is None else now_ns
    p=_validate(signed,gateway_key,now_ns)
    if p['target_key_id'] not in keys:raise ValueError('TARGET_KEY_UNAVAILABLE')
    with _connect(db) as conn:
        conn.execute('BEGIN IMMEDIATE')
        state=_check(conn,keys,checkpoint)
        if state['count']==0 or not hmac.compare_digest(state['head'],p['expected_head']):raise ValueError('APPROVAL_STALE_HEAD')
        old=state['active_key_id']; new=p['target_key_id']
        if new==old or hmac.compare_digest(keys[new],keys[old]):raise ValueError('TARGET_KEY_UNCHANGED')
        conn.execute(DDL)
        if conn.execute('SELECT 1 FROM epoch_target_approvals WHERE request_id=?',(p['request_id'],)).fetchone():raise ValueError('APPROVAL_REPLAY')
        # Approval and rotation commit together. No authorization is inferred from client role claims.
        result=_append(conn,keys,state,'ROTATE',new,old)
        conn.execute('INSERT INTO epoch_target_approvals VALUES (?,?,1,?)',
                     (p['request_id'],_canonical(signed).decode(),result['count']))
    return {**result,'request_id':p['request_id'],'approval_sha256':hashlib.sha256(_canonical(signed)).hexdigest(),
            'rotation_applied':True,'cutover_authorized':False,'production_qualified':False}
