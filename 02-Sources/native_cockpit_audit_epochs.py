"""V193.6: separate, transactionally rotated multi-epoch audit journal.

No implicit migration of legacy tables, no automatic key switch, no cutover.
All keys are caller-supplied; external checkpoint custody is caller-owned.
"""
import hashlib
import hmac
import re
import sqlite3
import time
import contextvars

_ROTATION_ADMITTED = contextvars.ContextVar("odmm_rotation_admitted", default=False)

def _sealed(conn):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='epoch_rotation_seal'").fetchone() is not None

def seal_rotation_apis(db, *, keys, checkpoint=None):
    """Explicit one-way DB seal. Caller must secure the SQLite file and key custody."""
    _keys(keys)
    with _connect(db) as conn:
        conn.execute("BEGIN IMMEDIATE")
        state=_check(conn,keys,checkpoint)
        if state["active_key_id"] is None: raise ValueError("ROTATION_SEAL_REQUIRES_EPOCH")
        conn.execute("CREATE TABLE IF NOT EXISTS epoch_rotation_seal(id INTEGER PRIMARY KEY CHECK(id=1), created_ns INTEGER NOT NULL)")
        conn.execute("INSERT OR IGNORE INTO epoch_rotation_seal VALUES (1,?)",(time.time_ns(),))
    return {"sealed":True,"head":state["head"],"production_qualified":False}
from native_benchmark_cockpit_adapter import _canonical, _mac, _secure_parent, GENESIS

_ID = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')

def _keys(keys):
    if not isinstance(keys, dict) or not keys or any(not isinstance(k,str) or not _ID.fullmatch(k) or not isinstance(v,bytes) or len(v)<32 for k,v in keys.items()):
        raise ValueError('EPOCH_KEYS_INVALID')

def _connect(db):
    path = _secure_parent(db)
    conn = sqlite3.connect(str(path),timeout=5)
    conn.execute('PRAGMA synchronous=FULL')
    return conn

def _check(conn, keys, checkpoint=None):
    rows = conn.execute('SELECT seq,kind,key_id,previous_sha256,detail,timestamp_ns,mac_sha256 FROM epoch_audit ORDER BY seq').fetchall()
    previous=GENESIS; active=None; count=0
    if checkpoint is not None:
        if not isinstance(checkpoint,dict) or type(checkpoint.get('count')) is not int or checkpoint['count']<0 or not isinstance(checkpoint.get('head'),str) or len(checkpoint['head'])!=64:
            raise ValueError('EPOCH_CHECKPOINT_INVALID')
        if len(rows)<checkpoint['count']: raise ValueError('EPOCH_ROLLBACK_DETECTED')
        if checkpoint['count']==0 and not hmac.compare_digest(previous,checkpoint['head']): raise ValueError('EPOCH_CHECKPOINT_MISMATCH')
    for seq,kind,kid,prev,detail,ts,mac in rows:
        count+=1
        if seq!=count or prev!=previous or kid not in keys: raise ValueError('EPOCH_CHAIN_INVALID')
        if (count==1 and kind!='START') or (count>1 and kind=='START'): raise ValueError('EPOCH_SEQUENCE_INVALID')
        if kind=='START':
            if active is not None or detail!='start':raise ValueError('EPOCH_SEQUENCE_INVALID')
        elif kind=='EVENT':
            if kid!=active or not isinstance(detail,str) or not detail.startswith('sha256:') or len(detail)!=71:raise ValueError('EPOCH_SEQUENCE_INVALID')
        elif kind=='ROTATE':
            if kid==active or detail!=active:raise ValueError('EPOCH_SEQUENCE_INVALID')
        else:raise ValueError('EPOCH_SEQUENCE_INVALID')
        record={'seq':seq,'kind':kind,'key_id':kid,'previous_sha256':prev,'detail':detail,'timestamp_ns':ts}
        if not isinstance(mac,str) or not hmac.compare_digest(mac,_mac(keys[kid],record)):raise ValueError('EPOCH_MAC_INVALID')
        previous=hashlib.sha256(_canonical({**record,'mac_sha256':mac})).hexdigest()
        if kind in ('START','ROTATE'):active=kid
        if checkpoint is not None and count==checkpoint['count'] and not hmac.compare_digest(previous,checkpoint['head']):raise ValueError('EPOCH_CHECKPOINT_MISMATCH')
    return {'count':count,'head':previous,'active_key_id':active}

def _append(conn, keys, state, kind, kid, detail):
    if kind == "ROTATE" and _sealed(conn) and not _ROTATION_ADMITTED.get():
        raise ValueError("LEGACY_ROTATION_SEALED")
    record={'seq':state['count']+1,'kind':kind,'key_id':kid,'previous_sha256':state['head'],'detail':detail,'timestamp_ns':time.time_ns()}
    mac=_mac(keys[kid],record)
    conn.execute('INSERT INTO epoch_audit(seq,kind,key_id,previous_sha256,detail,timestamp_ns,mac_sha256) VALUES (?,?,?,?,?,?,?)',(*record.values(),mac))
    return {'count':record['seq'],'head':hashlib.sha256(_canonical({**record,'mac_sha256':mac})).hexdigest(),'active_key_id':kid}

def transact_epoch(db, *, keys, operation, key_id=None, event_digest=None, checkpoint=None, expected_head=None):
    """START, EVENT, ROTATE. Full verification and append inside BEGIN IMMEDIATE.

    ROTATE requires all historical keys plus the new key, an externally approved
    decision at the caller, and expected_head binding to the observed journal.
    """
    _keys(keys)
    if operation not in ('START','EVENT','ROTATE'):raise ValueError('EPOCH_OPERATION_INVALID')
    with _connect(db) as conn:
        conn.execute('BEGIN IMMEDIATE')
        conn.execute('CREATE TABLE IF NOT EXISTS epoch_audit(seq INTEGER PRIMARY KEY,kind TEXT NOT NULL,key_id TEXT NOT NULL,previous_sha256 TEXT NOT NULL,detail TEXT NOT NULL,timestamp_ns INTEGER NOT NULL,mac_sha256 TEXT NOT NULL)')
        state=_check(conn,keys,checkpoint)
        if expected_head is not None and not hmac.compare_digest(state['head'],expected_head):raise ValueError('EPOCH_HEAD_CHANGED')
        if operation=='START':
            if state['count'] or key_id not in keys:raise ValueError('EPOCH_START_DENIED')
            result=_append(conn,keys,state,'START',key_id,'start')
        elif operation=='EVENT':
            if state['active_key_id'] is None or key_id not in (None,state['active_key_id']) or not isinstance(event_digest,str) or not re.fullmatch('[0-9a-f]{64}',event_digest):raise ValueError('EPOCH_EVENT_INVALID')
            result=_append(conn,keys,state,'EVENT',state['active_key_id'],'sha256:'+event_digest)
        else:
            if state['active_key_id'] is None or key_id not in keys or key_id==state['active_key_id'] or expected_head is None or hmac.compare_digest(keys[key_id],keys[state['active_key_id']]):raise ValueError('EPOCH_ROTATION_DENIED')
            result=_append(conn,keys,state,'ROTATE',key_id,state['active_key_id'])
    return {**result,'rotation_applied':operation=='ROTATE','cutover_authorized':False}

def verify_epochs(db, *, keys, checkpoint=None):
    _keys(keys)
    path=_secure_parent(db)
    if not path.exists():raise FileNotFoundError('EPOCH_AUDIT_ABSENT')
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as conn:
        conn.execute('BEGIN')
        state=_check(conn,keys,checkpoint)
    return {**state,'verified':True,'read_only':True,'cutover_authorized':False}
