"""V193.8: signed human review decisions, expiration and authenticated decision ledger.

A gateway verifies the human and their role BEFORE issuing a signed decision.
This module verifies gateway MAC and chain; it does not validate OIDC tokens.
Approval is recorded only: key rotation remains a separate explicit action.
"""
import hashlib
import hmac
import re
import sqlite3
import time
from native_benchmark_cockpit_adapter import _canonical, _mac
from native_cockpit_audit_epochs import _connect, _check, _keys

HEX = re.compile(r"[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9_.:@/-]{3,128}\Z")
DDL = """CREATE TABLE IF NOT EXISTS epoch_review_decisions(
 seq INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, decision TEXT NOT NULL,
 payload_json TEXT NOT NULL, previous_sha256 TEXT NOT NULL, mac_sha256 TEXT NOT NULL)"""

def sign_review(*, gateway_key, request_id, requester, reviewer, decision,
                expected_head, expires_ns, issued_ns=None):
    if not isinstance(gateway_key, bytes) or len(gateway_key)<32: raise ValueError('REVIEW_KEY_INVALID')
    if any(not isinstance(x,str) or not IDENT.fullmatch(x) for x in (request_id,requester,reviewer)) or requester==reviewer:
        raise ValueError('REVIEW_IDENTITY_INVALID')
    if decision not in ('APPROVE','DENY'): raise ValueError('REVIEW_DECISION_INVALID')
    if not isinstance(expected_head,str) or not HEX.fullmatch(expected_head): raise ValueError('REVIEW_HEAD_INVALID')
    if issued_ns is None: issued_ns=time.time_ns()
    if type(issued_ns) is not int or type(expires_ns) is not int or expires_ns<=issued_ns:
        raise ValueError('REVIEW_EXPIRY_INVALID')
    payload={'schema':'odmm.cockpit.review.decision.v1','request_id':request_id,'requester':requester,
             'reviewer':reviewer,'decision':decision,'expected_head':expected_head,
             'issued_ns':issued_ns,'expires_ns':expires_ns,'cutover_authorized':False}
    return {'payload':payload,'gateway_mac':_mac(gateway_key,payload)}

def _validate(signed,gateway_key,now_ns):
    if not isinstance(gateway_key,bytes) or len(gateway_key)<32:raise ValueError('REVIEW_KEY_INVALID')
    if not isinstance(signed,dict) or set(signed)!={'payload','gateway_mac'} or not isinstance(signed['payload'],dict):raise ValueError('REVIEW_FORMAT_INVALID')
    p=signed['payload']
    if set(p)!={'schema','request_id','requester','reviewer','decision','expected_head','issued_ns','expires_ns','cutover_authorized'}:raise ValueError('REVIEW_FORMAT_INVALID')
    if p['schema']!='odmm.cockpit.review.decision.v1' or p['cutover_authorized'] is not False or p['decision'] not in ('APPROVE','DENY'):raise ValueError('REVIEW_CONTEXT_INVALID')
    if any(not isinstance(p[k],str) or not IDENT.fullmatch(p[k]) for k in ('request_id','requester','reviewer')) or p['requester']==p['reviewer']:raise ValueError('REVIEW_IDENTITY_INVALID')
    if not isinstance(p['expected_head'],str) or not HEX.fullmatch(p['expected_head']):raise ValueError('REVIEW_HEAD_INVALID')
    if type(p['issued_ns']) is not int or type(p['expires_ns']) is not int or p['expires_ns']<=p['issued_ns'] or type(now_ns) is not int or now_ns<p['issued_ns'] or now_ns>=p['expires_ns']:raise ValueError('REVIEW_EXPIRED_OR_NOT_YET_VALID')
    if not isinstance(signed['gateway_mac'],str) or not hmac.compare_digest(signed['gateway_mac'],_mac(gateway_key,p)):raise ValueError('REVIEW_MAC_INVALID')
    return p

def _check_ledger(conn,ledger_key):
    prev='0'*64
    rows=conn.execute('SELECT seq,request_id,decision,payload_json,previous_sha256,mac_sha256 FROM epoch_review_decisions ORDER BY seq').fetchall()
    for idx,(seq,rid,decision,raw,previous,mac) in enumerate(rows,1):
        record={'seq':seq,'request_id':rid,'decision':decision,'payload_json':raw,'previous_sha256':previous}
        if seq!=idx or previous!=prev or not hmac.compare_digest(str(mac),_mac(ledger_key,record)):raise ValueError('REVIEW_LEDGER_TAMPERED')
        prev=hashlib.sha256(_canonical({**record,'mac_sha256':mac})).hexdigest()
    return {'count':len(rows),'head':prev}

def record_review(db,*,keys,signed,gateway_key,ledger_key,checkpoint=None,now_ns=None):
    _keys(keys)
    if not isinstance(ledger_key,bytes) or len(ledger_key)<32:raise ValueError('REVIEW_LEDGER_KEY_INVALID')
    now_ns=time.time_ns() if now_ns is None else now_ns
    p=_validate(signed,gateway_key,now_ns)
    with _connect(db) as conn:
        conn.execute('BEGIN IMMEDIATE')
        # Existing epoch journal must already exist; never create/repair it here.
        state=_check(conn,keys,checkpoint)
        if state['count']==0 or not hmac.compare_digest(state['head'],p['expected_head']):raise ValueError('REVIEW_STALE_HEAD')
        conn.execute(DDL)
        conn.execute('''CREATE TABLE IF NOT EXISTS epoch_review_revocations(request_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, gateway_mac TEXT NOT NULL, recorded_ns INTEGER NOT NULL)''')
        ledger=_check_ledger(conn,ledger_key)
        if conn.execute('SELECT 1 FROM epoch_review_decisions WHERE request_id=?',(p['request_id'],)).fetchone():raise ValueError('REVIEW_REPLAY')
        raw=_canonical(signed).decode('utf-8')
        rec={'seq':ledger['count']+1,'request_id':p['request_id'],'decision':p['decision'],'payload_json':raw,'previous_sha256':ledger['head']}
        mac=_mac(ledger_key,rec)
        conn.execute('INSERT INTO epoch_review_decisions VALUES (?,?,?,?,?,?)',(*rec.values(),mac))
        head=hashlib.sha256(_canonical({**rec,'mac_sha256':mac})).hexdigest()
    return {'decision':p['decision'],'recorded':True,'count':rec['seq'],'head':head,'rotation_applied':False,'cutover_authorized':False}

def verify_reviews(db,*,ledger_key,trusted_head=None):
    if not isinstance(ledger_key,bytes) or len(ledger_key)<32:raise ValueError('REVIEW_LEDGER_KEY_INVALID')
    from native_benchmark_cockpit_adapter import _secure_parent
    path=_secure_parent(db)
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as conn:
        conn.execute('BEGIN')
        state=_check_ledger(conn,ledger_key)
    if trusted_head is not None and not hmac.compare_digest(state['head'],trusted_head):raise ValueError('REVIEW_LEDGER_ROLLBACK')
    return {**state,'verified':True,'read_only':True,'external_anchor_recommended':True}
