"""V194.4: append-only HMAC revocation journal; independent head is mandatory for gated rotation."""
import hashlib, hmac, sqlite3, time
from native_benchmark_cockpit_adapter import _canonical, _mac
from native_cockpit_audit_epochs import _connect

DDL = """CREATE TABLE IF NOT EXISTS epoch_revocation_chain(seq INTEGER PRIMARY KEY,request_id TEXT NOT NULL UNIQUE,reason_sha256 TEXT NOT NULL,recorded_ns INTEGER NOT NULL,previous_sha256 TEXT NOT NULL,mac_sha256 TEXT NOT NULL)"""
GENESIS='0'*64

def _verify(conn,key):
    if not isinstance(key,bytes) or len(key)<32: raise ValueError('REVOCATION_KEY_INVALID')
    previous=GENESIS; count=0; revoked=set()
    try: rows=conn.execute('SELECT seq,request_id,reason_sha256,recorded_ns,previous_sha256,mac_sha256 FROM epoch_revocation_chain ORDER BY seq').fetchall()
    except sqlite3.OperationalError as exc: raise ValueError('REVOCATION_CHAIN_MISSING') from exc
    for seq,rid,digest,ts,prev,mac in rows:
        count+=1
        rec={'seq':seq,'request_id':rid,'reason_sha256':digest,'recorded_ns':ts,'previous_sha256':prev}
        if seq!=count or not isinstance(rid,str) or not rid or rid in revoked or not isinstance(digest,str) or len(digest)!=64 or prev!=previous or not isinstance(mac,str) or not hmac.compare_digest(mac,_mac(key,rec)):
            raise ValueError('REVOCATION_CHAIN_TAMPERED')
        previous=hashlib.sha256(_canonical({**rec,'mac_sha256':mac})).hexdigest();revoked.add(rid)
    return {'count':count,'head':previous,'revoked':revoked}

def initialize_revocations(db,*,revocation_key):
    with _connect(db) as conn:
        conn.execute('BEGIN IMMEDIATE');conn.execute(DDL)
        state=_verify(conn,revocation_key)
    return {'count':state['count'],'head':state['head']}

def append_revocation(db,*,revocation_key,request_id,reason,expected_head):
    if not isinstance(request_id,str) or not request_id or len(request_id)>128 or not isinstance(reason,str) or not reason: raise ValueError('REVOCATION_INPUT_INVALID')
    with _connect(db) as conn:
        conn.execute('BEGIN IMMEDIATE');state=_verify(conn,revocation_key)
        if not isinstance(expected_head,str) or not hmac.compare_digest(state['head'],expected_head):raise ValueError('REVOCATION_STALE_HEAD')
        if request_id in state['revoked']:raise ValueError('REVOCATION_DUPLICATE')
        rec={'seq':state['count']+1,'request_id':request_id,'reason_sha256':hashlib.sha256(reason.encode()).hexdigest(),'recorded_ns':time.time_ns(),'previous_sha256':state['head']}
        mac=_mac(revocation_key,rec)
        conn.execute('INSERT INTO epoch_revocation_chain VALUES (?,?,?,?,?,?)',(*rec.values(),mac))
        head=hashlib.sha256(_canonical({**rec,'mac_sha256':mac})).hexdigest()
    return {'count':rec['seq'],'head':head,'request_id':request_id}

def verify_revocations(db,*,revocation_key,expected_head):
    with _connect(db) as conn:
        conn.execute('BEGIN');state=_verify(conn,revocation_key)
        if not isinstance(expected_head,str) or not hmac.compare_digest(state['head'],expected_head):raise ValueError('REVOCATION_ANCHOR_MISMATCH')
    return {'count':state['count'],'head':state['head'],'verified':True}
