"""V193.7: fail-closed, transactional approval of an epoch key rotation.

The trusted authentication gateway MUST authenticate and authorize the reviewer;
this module verifies its HMAC assertion, not OIDC tokens. The reviewer cannot
be the requester. Requests are consumed atomically with the ROTATE record.
"""
import hashlib
import hmac
import re
import sqlite3
from native_benchmark_cockpit_adapter import _canonical
from native_cockpit_audit_epochs import _keys, _connect, _check, _append, GENESIS

ID = re.compile(r'^[A-Za-z0-9_.:@/-]{3,128}$')

def sign_approval(*, gateway_key, request_id, requester, reviewer, old_key_id, new_key_id, expected_head):
    if not isinstance(gateway_key,bytes) or len(gateway_key)<32: raise ValueError('GATEWAY_KEY_INVALID')
    values=(request_id,requester,reviewer,old_key_id,new_key_id)
    if any(not isinstance(x,str) or not ID.fullmatch(x) for x in values) or requester==reviewer: raise ValueError('APPROVAL_IDENTITY_INVALID')
    if not isinstance(expected_head,str) or not re.fullmatch('[0-9a-f]{64}',expected_head):raise ValueError('APPROVAL_HEAD_INVALID')
    payload={'schema':'odmm.cockpit.epoch.approval.v1','request_id':request_id,'requester':requester,'reviewer':reviewer,'old_key_id':old_key_id,'new_key_id':new_key_id,'expected_head':expected_head,'decision':'APPROVE_ROTATION','cutover_authorized':False}
    return {'payload':payload,'gateway_mac':hmac.new(gateway_key,_canonical(payload),hashlib.sha256).hexdigest()}

def apply_approved_rotation(db, *, keys, approval, gateway_key, checkpoint=None):
    _keys(keys)
    if not isinstance(gateway_key,bytes) or len(gateway_key)<32:raise ValueError('GATEWAY_KEY_INVALID')
    if not isinstance(approval,dict) or set(approval)!={'payload','gateway_mac'} or not isinstance(approval['payload'],dict):raise ValueError('APPROVAL_FORMAT_INVALID')
    p=approval['payload']
    if set(p)!={'schema','request_id','requester','reviewer','old_key_id','new_key_id','expected_head','decision','cutover_authorized'}:raise ValueError('APPROVAL_FORMAT_INVALID')
    if p['schema']!='odmm.cockpit.epoch.approval.v1' or p['decision']!='APPROVE_ROTATION' or p['cutover_authorized'] is not False:raise ValueError('APPROVAL_CONTEXT_INVALID')
    if any(not isinstance(p[k],str) or not ID.fullmatch(p[k]) for k in ('request_id','requester','reviewer','old_key_id','new_key_id')) or p['requester']==p['reviewer']:raise ValueError('APPROVAL_IDENTITY_INVALID')
    if not isinstance(p['expected_head'],str) or not re.fullmatch('[0-9a-f]{64}',p['expected_head']):raise ValueError('APPROVAL_HEAD_INVALID')
    mac=approval['gateway_mac']
    if not isinstance(mac,str) or not hmac.compare_digest(mac,hmac.new(gateway_key,_canonical(p),hashlib.sha256).hexdigest()):raise ValueError('APPROVAL_MAC_INVALID')
    with _connect(db) as conn:
        conn.execute('BEGIN IMMEDIATE')
        # No migration of old tables; replay ledger is local to the new epoch DB.
        conn.execute('CREATE TABLE IF NOT EXISTS epoch_audit(seq INTEGER PRIMARY KEY,kind TEXT NOT NULL,key_id TEXT NOT NULL,previous_sha256 TEXT NOT NULL,detail TEXT NOT NULL,timestamp_ns INTEGER NOT NULL,mac_sha256 TEXT NOT NULL)')
        conn.execute('CREATE TABLE IF NOT EXISTS epoch_approval_use(request_id TEXT PRIMARY KEY, reviewer TEXT NOT NULL, approval_sha256 TEXT NOT NULL, rotation_seq INTEGER NOT NULL)')
        state=_check(conn,keys,checkpoint)
        if state['count']==0 or state['head']!=p['expected_head'] or state['active_key_id']!=p['old_key_id']:raise ValueError('APPROVAL_STALE_HEAD')
        if p['new_key_id'] not in keys or p['old_key_id'] not in keys or p['new_key_id']==p['old_key_id'] or hmac.compare_digest(keys[p['new_key_id']],keys[p['old_key_id']]):raise ValueError('APPROVAL_KEY_INVALID')
        if conn.execute('SELECT 1 FROM epoch_approval_use WHERE request_id=?',(p['request_id'],)).fetchone():raise ValueError('APPROVAL_REPLAY')
        result=_append(conn,keys,state,'ROTATE',p['new_key_id'],p['old_key_id'])
        conn.execute('INSERT INTO epoch_approval_use VALUES (?,?,?,?)',(p['request_id'],p['reviewer'],hashlib.sha256(_canonical(approval)).hexdigest(),result['count']))
    return {**result,'approval_recorded':True,'rotation_applied':True,'cutover_authorized':False}
