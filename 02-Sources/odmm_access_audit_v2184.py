"""Transactional, tamper-evident local audit of isolated access campaigns.

Evidence is local only: never implies AD/LDAP authentication or NAS qualification.
Author: Abdelhalim Talbi.
"""
import hashlib
import json
import os
import sqlite3
from pathlib import Path

class AuditError(RuntimeError):
    pass

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def _connect(path):
    db = sqlite3.connect(str(path), timeout=10, isolation_level=None)
    db.execute('PRAGMA busy_timeout=10000')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, previous TEXT NOT NULL, payload TEXT NOT NULL, hash TEXT NOT NULL)')
    return db

def _verify_rows(rows):
    previous='0'*64
    for expected,(seq,prev,payload,stored) in enumerate(rows,1):
        if seq!=expected or prev!=previous:
            raise AuditError('CHAIN_BROKEN')
        try:
            item=json.loads(payload)
        except (ValueError,TypeError) as exc:
            raise AuditError('INVALID_PAYLOAD') from exc
        if canonical(item).decode()!=payload or digest({'seq':seq,'previous':prev,'payload':item})!=stored:
            raise AuditError('TAMPER_DETECTED')
        previous=stored
    return previous

def append_campaign(path, campaign, *, expected_head=None):
    """Append atomically. expected_head provides explicit CAS for concurrent operators."""
    if not isinstance(campaign,dict) or not isinstance(campaign.get('report'),dict):
        raise AuditError('INVALID_CAMPAIGN')
    report=campaign['report']
    if (campaign.get('sha256')!=digest(report) or report.get('cutover_authorized') is not False
        or report.get('nas_qualified') is not False or report.get('dedicated_account_attested') is not False):
        raise AuditError('UNTRUSTED_CAMPAIGN')
    if not isinstance(path,(str,os.PathLike)) or Path(path).is_symlink():
        raise AuditError('INVALID_DB_PATH')
    db=_connect(path)
    try:
        db.execute('BEGIN IMMEDIATE')
        rows=db.execute('SELECT seq,previous,payload,hash FROM audit ORDER BY seq').fetchall()
        head=_verify_rows(rows)
        if expected_head is not None and expected_head!=head:
            raise AuditError('STALE_HEAD')
        seq=len(rows)+1
        payload={'schema':'odmm.access-audit.v2184','campaign':campaign,
                 'identity':{'euid':os.geteuid(),'egid':os.getegid(), 'authentication':'LOCAL_OS_ONLY'},
                 'cutover_authorized':False}
        h=digest({'seq':seq,'previous':head,'payload':payload})
        db.execute('INSERT INTO audit VALUES(?,?,?,?)',(seq,head,canonical(payload).decode(),h))
        db.execute('COMMIT')
        return {'seq':seq,'head':h,'cutover_authorized':False}
    except Exception:
        if db.in_transaction: db.execute('ROLLBACK')
        raise
    finally:
        db.close()

def verify_audit(path):
    if Path(path).is_symlink() or not Path(path).is_file():
        raise AuditError('INVALID_DB_PATH')
    db=_connect(path)
    try:
        db.execute('BEGIN')
        rows=db.execute('SELECT seq,previous,payload,hash FROM audit ORDER BY seq').fetchall()
        head=_verify_rows(rows)
        db.execute('COMMIT')
        return {'entries':len(rows),'head':head,'verified':True,'nas_qualified':False,'cutover_authorized':False}
    finally:
        db.close()
