"""V193.2 audit verification, external anchor export, and explicit legacy quarantine.

An anchor file is NOT an independent trust store. Operators must retain its digest
outside the ODMM host to detect complete rollback or coordinated replacement.
"""
import hashlib
import json
import os
import sqlite3
import stat
from pathlib import Path
from native_benchmark_cockpit_adapter import _canonical, _mac, _secure_parent, GENESIS
import hmac


def verify_access_audit(db_path, *, audit_key, trusted_head=None):
    if not isinstance(audit_key, bytes) or len(audit_key) < 32:
        raise ValueError('AUDIT_KEY_REQUIRED')
    path = _secure_parent(db_path)
    if not path.exists():
        raise FileNotFoundError('AUDIT_NOT_FOUND')
    # Read-only SQLite URI prevents accidentally creating a replacement DB.
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5) as conn:
        conn.execute('BEGIN')
        rows = conn.execute('SELECT id,timestamp_ns,subject_sha256,action,outcome,manifest_sha256,'
                            'previous_sha256,mac_sha256 FROM evidence_access_log ORDER BY id').fetchall()
        previous = GENESIS
        for index, (seq, ts, subject, action, outcome, manifest, prev, mac) in enumerate(rows, 1):
            record = {'seq':seq,'timestamp_ns':ts,'subject_sha256':subject,'action':action,
                      'outcome':outcome,'manifest_sha256':manifest,'previous_sha256':prev}
            if seq != index or prev != previous or not isinstance(mac,str) or not hmac.compare_digest(mac, _mac(audit_key,record)):
                raise ValueError('AUDIT_CHAIN_INVALID')
            previous = hashlib.sha256(_canonical({**record,'mac_sha256':mac})).hexdigest()
        if trusted_head is not None and not hmac.compare_digest(previous,trusted_head):
            raise ValueError('AUDIT_TRUSTED_HEAD_MISMATCH')
        conn.commit()
    return {'schema':'odmm.cockpit.audit.anchor.v1','count':len(rows),
            'head_sha256':previous,'read_only':True,'cutover_authorized':False,
            'external_trust_required':True}


def export_anchor(db_path, destination, *, audit_key, trusted_head=None):
    """Export a candidate anchor, never overwrite. Externally retain/attest digest."""
    status = verify_access_audit(db_path,audit_key=audit_key,trusted_head=trusted_head)
    path = _secure_parent(destination)
    data = _canonical(status)+b'\n'
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        parent_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent_fd)
        finally:os.close(parent_fd)
    finally:os.close(fd)
    return {**status,'anchor_file_sha256':hashlib.sha256(data).hexdigest()}


def inspect_legacy_audit(db_path):
    """Inventory legacy SQLite without importing unauthenticated entries."""
    path=_secure_parent(db_path)
    if not path.exists():raise FileNotFoundError('LEGACY_AUDIT_NOT_FOUND')
    with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as conn:
        tables=[row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        counts={}
        for table in tables:
            if not table.startswith('sqlite_'):
                escaped='"'+table.replace('"','""')+'"'
                counts[table]=conn.execute('SELECT count(*) FROM '+escaped).fetchone()[0]
    return {'schema':'odmm.cockpit.legacy.inventory.v1','tables':counts,
            'migration_state':'QUARANTINED_REVIEW_REQUIRED','legacy_authenticated':False,
            'automatic_import':False,'source_read_only':True,'cutover_authorized':False}


def verify_access_audit_prefix(db_path, *, audit_key, checkpoint_count, checkpoint_head):
    """Read-only HMAC verification with exact historical checkpoint matching."""
    if type(checkpoint_count) is not int or checkpoint_count < 0 or not isinstance(checkpoint_head, str) or len(checkpoint_head) != 64:
        raise ValueError('AUDIT_CHECKPOINT_INVALID')
    if not isinstance(audit_key, bytes) or len(audit_key) < 32:
        raise ValueError('AUDIT_KEY_REQUIRED')
    path = _secure_parent(db_path)
    if not path.exists():
        raise FileNotFoundError('AUDIT_NOT_FOUND')
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5) as conn:
        conn.execute('BEGIN')
        rows = conn.execute('SELECT id,timestamp_ns,subject_sha256,action,outcome,manifest_sha256,'
                            'previous_sha256,mac_sha256 FROM evidence_access_log ORDER BY id').fetchall()
        if len(rows) < checkpoint_count:
            raise ValueError('AUDIT_ROLLBACK_DETECTED')
        previous = GENESIS
        if checkpoint_count == 0 and not hmac.compare_digest(previous, checkpoint_head):
            raise ValueError('AUDIT_CHECKPOINT_MISMATCH')
        for index, (seq, ts, subject, action, outcome, manifest, prev, mac) in enumerate(rows, 1):
            record = {'seq':seq,'timestamp_ns':ts,'subject_sha256':subject,'action':action,
                      'outcome':outcome,'manifest_sha256':manifest,'previous_sha256':prev}
            if seq != index or prev != previous or not isinstance(mac, str) or not hmac.compare_digest(mac, _mac(audit_key, record)):
                raise ValueError('AUDIT_CHAIN_INVALID')
            previous = hashlib.sha256(_canonical({**record,'mac_sha256':mac})).hexdigest()
            if index == checkpoint_count and not hmac.compare_digest(previous, checkpoint_head):
                raise ValueError('AUDIT_CHECKPOINT_MISMATCH')
        conn.commit()
    return {'schema':'odmm.cockpit.audit.anchor.v1','count':len(rows),
            'head_sha256':previous,'checkpoint_count':checkpoint_count,
            'checkpoint_verified':True,'read_only':True,'cutover_authorized':False,
            'external_trust_required':True}
