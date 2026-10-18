"""ODMM V204.3: durable fail-closed fidelity evidence gate (local read-only comparison).
Auteur : Abdelhalim Talbi. Not a NAS certification or cutover approval.
"""
import hashlib, json, os, sqlite3, time
from pathlib import Path
from native_extended_fidelity_v2042 import compare_trees, FIELDS

SCHEMA = "odmm.fidelity_gate.v2043"

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()

def record(db_path, campaign_id, source, target, *, required=("content", "mode", "uid", "gid", "mtime_ns", "xattrs", "hardlinks", "nfs4_acl", "smb_acl", "smb_ads")):
    """Persist assessment transactionally. No migration/cutover side effects."""
    if not isinstance(campaign_id,str) or not campaign_id.strip(): raise ValueError("INVALID_CAMPAIGN")
    if not required or any(f not in FIELDS for f in required): raise ValueError("INVALID_REQUIREMENTS")
    p=Path(db_path)
    if p.is_symlink() or (p.exists() and not p.is_file()): raise ValueError("UNSAFE_REGISTRY")
    report=compare_trees(source,target,required=required)
    report['required']=list(required)
    report['schema']=SCHEMA
    report['campaign_id']=campaign_id
    report['validation_authorized']=False
    report['cutover_authorized']=False
    digest=hashlib.sha256(_canonical(report)).hexdigest()
    con=sqlite3.connect(p,timeout=10)
    try:
        con.execute('PRAGMA synchronous=FULL')
        con.execute('CREATE TABLE IF NOT EXISTS fidelity_assessments (id INTEGER PRIMARY KEY, campaign TEXT NOT NULL, timestamp_ns INTEGER NOT NULL, report_json TEXT NOT NULL, sha256 TEXT NOT NULL)')
        con.execute('BEGIN IMMEDIATE')
        con.execute('INSERT INTO fidelity_assessments(campaign,timestamp_ns,report_json,sha256) VALUES (?,?,?,?)',(campaign_id,time.time_ns(),_canonical(report).decode(),digest))
        con.commit()
    except BaseException:
        con.rollback(); raise
    finally: con.close()
    return {'status':report['status'],'sha256':digest,'validation_authorized':False,'cutover_authorized':False,'report':report}

def history(db_path,campaign_id):
    p=Path(db_path)
    if not p.is_file() or p.is_symlink(): raise FileNotFoundError('REGISTRY_MISSING_OR_UNSAFE')
    con=sqlite3.connect('file:'+__import__('urllib.parse',fromlist=['quote']).quote(str(p.resolve()),safe='/')+'?mode=ro',uri=True)
    try:
        rows=con.execute('SELECT report_json,sha256 FROM fidelity_assessments WHERE campaign=? ORDER BY id',(campaign_id,)).fetchall()
        out=[]
        for raw,digest in rows:
            data=json.loads(raw)
            if hashlib.sha256(_canonical(data)).hexdigest()!=digest: raise ValueError('AUDIT_TAMPERED')
            out.append(data)
        return out
    finally: con.close()

def decision(report):
    """A MATCH is only local evidence, never production authorization."""
    return {'fidelity_status':report['status'],'ready_for_manual_review':report['status']=='MATCH','validation_authorized':False,'cutover_authorized':False,'unverified':report['unverified'],'mismatches':report['mismatches']}
