"""Separate SQLite anchor for local access-audit campaigns (not remote/WORM).

Cross-database commit is intentionally fail-closed: a crash after audit commit
leaves an unresolved mismatch, requiring explicit operator reconciliation.
Author: Abdelhalim Talbi.
"""
import os
import sqlite3
from pathlib import Path
from odmm_access_audit_v2184 import append_campaign, verify_audit, AuditError

GENESIS='0'*64

def _open(path):
    path=Path(path)
    if path.is_symlink(): raise AuditError('INVALID_ANCHOR_PATH')
    db=sqlite3.connect(str(path),timeout=10,isolation_level=None)
    db.execute('PRAGMA busy_timeout=10000')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE IF NOT EXISTS anchor (id INTEGER PRIMARY KEY CHECK(id=1), seq INTEGER NOT NULL, head TEXT NOT NULL)')
    return db

def _read(db):
    row=db.execute('SELECT seq,head FROM anchor WHERE id=1').fetchone()
    return {'entries':row[0],'head':row[1]} if row else {'entries':0,'head':GENESIS}

def _check_paths(audit_path,anchor_path):
    if Path(audit_path).resolve()==Path(anchor_path).resolve():
        raise AuditError('ANCHOR_NOT_INDEPENDENT')

def verify_anchored(audit_path,anchor_path):
    _check_paths(audit_path,anchor_path)
    if not Path(anchor_path).is_file(): raise AuditError('ANCHOR_MISSING')
    db=_open(anchor_path)
    try:
        db.execute('BEGIN')
        anchored=_read(db)
        observed=verify_audit(audit_path)
        if (anchored['entries'],anchored['head']) != (observed['entries'],observed['head']):
            raise AuditError('ANCHOR_MISMATCH_RECONCILIATION_REQUIRED')
        return {**observed,'anchored':True,'anchor_backend':'SEPARATE_LOCAL_SQLITE_NOT_WORM'}
    finally:
        db.close()

def append_anchored(audit_path,anchor_path,campaign,*,expected_head=None):
    _check_paths(audit_path,anchor_path)
    db=_open(anchor_path)
    try:
        db.execute('BEGIN IMMEDIATE')  # serialize writers across processes
        anchored=_read(db)
        if Path(audit_path).exists():
            observed=verify_audit(audit_path)
        else:
            observed={'entries':0,'head':GENESIS}
        if (anchored['entries'],anchored['head']) != (observed['entries'],observed['head']):
            raise AuditError('ANCHOR_MISMATCH_RECONCILIATION_REQUIRED')
        if expected_head is not None and expected_head!=anchored['head']:
            raise AuditError('STALE_HEAD')
        result=append_campaign(audit_path,campaign,expected_head=anchored['head'])
        db.execute('INSERT INTO anchor(id,seq,head) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET seq=excluded.seq,head=excluded.head',(result['seq'],result['head']))
        db.execute('COMMIT')
        return {**result,'anchored':True}
    except Exception:
        if db.in_transaction: db.execute('ROLLBACK')
        raise
    finally:
        db.close()

def reconcile_anchored(audit_path,anchor_path,*,approved=False,expected_audit_head=None):
    """Explicit local repair, NOT evidence of external trust or authorization."""
    if not approved: raise AuditError('OPERATOR_APPROVAL_REQUIRED')
    _check_paths(audit_path,anchor_path)
    db=_open(anchor_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        current=_read(db)
        observed=verify_audit(audit_path)
        if expected_audit_head!=observed['head']: raise AuditError('STALE_AUDIT_HEAD')
        if observed['entries']<current['entries']: raise AuditError('ANCHOR_AHEAD')
        if observed['entries']==current['entries'] and observed['head']!=current['head']:
            raise AuditError('CONFLICTING_HEAD')
        # For append-only recovery, check the anchored prefix, not merely the final hash.
        if current['entries']:
            from odmm_access_audit_v2184 import _connect
            audit=_connect(audit_path)
            try:
                prefix=audit.execute('SELECT hash FROM audit WHERE seq=?',(current['entries'],)).fetchone()
                if prefix is None or prefix[0]!=current['head']: raise AuditError('ANCHOR_PREFIX_MISMATCH')
            finally: audit.close()
        db.execute('INSERT INTO anchor(id,seq,head) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET seq=excluded.seq,head=excluded.head',(observed['entries'],observed['head']))
        db.execute('COMMIT')
        return {'reconciled':True,'entries':observed['entries'],'head':observed['head'],'cutover_authorized':False}
    except Exception:
        if db.in_transaction: db.execute('ROLLBACK')
        raise
    finally: db.close()
