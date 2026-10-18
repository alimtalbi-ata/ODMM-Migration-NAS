"""V203.1: consistent SQLite snapshot and independently verifiable audit export.
Author: Abdelhalim Talbi. Read-only against source registry; local snapshot only.
"""
import hashlib
import contextlib
import json
import sqlite3
from pathlib import Path
from odmm_campaign_registry_v2029 import digest

SCHEMA='odmm.registry.resilience.v2031'
TABLES=('campaigns','observations','signed_evidence','audit_chain')

def _connect(path):
    p=Path(path)
    if not p.is_file() or p.is_symlink(): raise ValueError('REGISTRY_MISSING_OR_SYMLINK')
    db=sqlite3.connect('file:'+str(p.resolve())+'?mode=ro',uri=True,timeout=10)
    db.execute('PRAGMA query_only=ON')
    return db

def _inspect(db):
    if db.execute('PRAGMA integrity_check').fetchone() != ('ok',): raise ValueError('SQLITE_INTEGRITY_FAILED')
    if db.execute('PRAGMA foreign_key_check').fetchall(): raise ValueError('FOREIGN_KEY_FAILURE')
    present={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not set(TABLES).issubset(present): raise ValueError('MISSING_TABLE')
    rows={t:db.execute('SELECT * FROM '+t+' ORDER BY '+('seq' if t=='audit_chain' else 'rowid')).fetchall() for t in TABLES}
    manifest={c[0]:set(json.loads(c[1])) for c in rows['campaigns']}
    for c,assets,h in rows['campaigns']:
        if digest(sorted(json.loads(assets)))!=h: raise ValueError('MANIFEST_HASH_MISMATCH')
    signed={}
    for eid,c,a,side,encoded,kid in rows['signed_evidence']:
        if c not in manifest or a not in manifest[c] or side not in ('source','target'):
            raise ValueError('INVALID_SIGNED_EVIDENCE_REFERENCE')
        if hashlib.sha256(encoded.encode()).hexdigest()!=eid: raise ValueError('ENVELOPE_DIGEST_MISMATCH')
        if (c,a,side) in signed: raise ValueError('DUPLICATE_SIGNED_SIDE')
        signed[(c,a,side)]=(eid,kid)
    observations={}
    for c,a,side,eid,result,h in rows['observations']:
        if c not in manifest or a not in manifest[c] or side not in ('source','target'):
            raise ValueError('ORPHAN_OBSERVATION')
        observations[(c,a,side)]=(eid,h)
    if set(signed)!=set(observations): raise ValueError('EVIDENCE_OBSERVATION_DIVERGENCE')
    for key,(eid,kid) in signed.items():
        if observations[key]!=(eid,eid): raise ValueError('EVIDENCE_OBSERVATION_MISMATCH')
    prev='0'*64
    for i,(seq,previous,event_json,event_hash) in enumerate(rows['audit_chain'],1):
        if seq!=i or previous!=prev: raise ValueError('AUDIT_SEQUENCE_BROKEN')
        event=json.loads(event_json)
        if digest({'previous_hash':previous,'event':event})!=event_hash: raise ValueError('AUDIT_HASH_BROKEN')
        key=(event.get('campaign_id'),event.get('asset'),event.get('side'))
        if key not in signed or signed[key]!=(event.get('evidence_id'),event.get('key_id')):
            raise ValueError('AUDIT_EVIDENCE_MISMATCH')
        prev=event_hash
    if len(rows['audit_chain'])!=len(signed): raise ValueError('AUDIT_COUNT_MISMATCH')
    return rows,prev

def export(path):
    db=_connect(path)
    try:
        # Single consistent read transaction; WAL writers may proceed concurrently.
        db.execute('BEGIN')
        rows,head=_inspect(db)
        data={'schema':SCHEMA,'author':'Abdelhalim Talbi','tables':{t:[list(row) for row in rows[t]] for t in TABLES},
              'chain_head':head,'counts':{t:len(rows[t]) for t in TABLES},
              'cutover_authorized':False,'writes_to_nas':False,'native_engine_default':True,'silent_fallback_allowed':False}
        data['report_sha256']=digest(data)
        return data
    finally: db.close()

def verify_export(data):
    if not isinstance(data,dict) or data.get('schema')!=SCHEMA: return False
    if any(data.get(k)!=v for k,v in [('cutover_authorized',False),('writes_to_nas',False),('native_engine_default',True),('silent_fallback_allowed',False)]): return False
    try:
        if digest({k:v for k,v in data.items() if k!='report_sha256'})!=data['report_sha256']: return False
        from tempfile import TemporaryDirectory
        from odmm_integrated_registry_v2030 import IntegratedRegistry
        with TemporaryDirectory() as tmp:
            p=Path(tmp)/'verification.db'
            IntegratedRegistry(p)
            with contextlib.closing(sqlite3.connect(p)) as db, db:
                for t in TABLES: db.execute('DELETE FROM '+t)
                for t in TABLES:
                    for row in data['tables'][t]:
                        db.execute('INSERT INTO '+t+' VALUES ('+','.join('?' for _ in row)+')',row)
                checked,head=_inspect(db)
                return head==data['chain_head'] and all(len(checked[t])==data['counts'][t] for t in TABLES)
    except (ValueError,TypeError,KeyError,sqlite3.Error,OverflowError): return False

def snapshot(source,destination):
    src=Path(source); dst=Path(destination)
    if dst.exists() or dst.is_symlink(): raise ValueError('DESTINATION_EXISTS')
    if not dst.parent.is_dir(): raise ValueError('DESTINATION_PARENT_MISSING')
    db=_connect(src)
    try:
        _inspect(db)
        with contextlib.closing(sqlite3.connect(dst)) as target: db.backup(target)
        with contextlib.closing(_connect(dst)) as check: _inspect(check)
        return export(dst)
    except Exception:
        dst.unlink(missing_ok=True)
        raise
    finally: db.close()
