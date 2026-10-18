"""V193.1 read-only ODMM evidence adapter with fail-closed HMAC chained access audit.

The caller supplies a server-verified identity and a separately managed audit key.
This is a library adapter, not a deployed authentication middleware.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import time
from pathlib import Path
from native_benchmark_cockpit_panel import cockpit_panel, cockpit_status

ROLES = frozenset({'evidence_viewer', 'security_auditor', 'odmm_admin'})
GENESIS = '0' * 64


def _principal(principal):
    if not isinstance(principal, dict) or principal.get('authenticated') is not True:
        raise PermissionError('AUTHENTICATION_REQUIRED')
    subject = principal.get('subject')
    roles = principal.get('roles')
    if not isinstance(subject, str) or not (1 <= len(subject) <= 256) or not isinstance(roles, (list, tuple, set)):
        raise PermissionError('IDENTITY_INVALID')
    if not all(isinstance(r, str) for r in roles) or not ROLES.intersection(roles):
        raise PermissionError('EVIDENCE_VIEW_DENIED')
    return subject


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _mac(key, record):
    return hmac.new(key, _canonical(record), hashlib.sha256).hexdigest()


def _secure_parent(path):
    """Reject symlinks in existing path components; not a race-free path capability."""
    path = Path(path).absolute()
    for parent in [*reversed(path.parent.parents), path.parent]:
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError('AUDIT_DIRECTORY_UNSAFE')
    if path.is_symlink():
        raise ValueError('AUDIT_PATH_SYMLINK')
    if path.exists() and not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('AUDIT_PATH_NOT_REGULAR')
    return path


def _audit(db_path, subject, action, outcome, manifest_digest, audit_key, trusted_audit_head=None, trusted_checkpoint_count=None):
    if not isinstance(audit_key, bytes) or len(audit_key) < 32:
        raise ValueError('AUDIT_KEY_REQUIRED')
    path = _secure_parent(db_path)
    # SQLite is transactional, but path replacement remains a threat if directory is writable
    # by an untrusted principal. Use a trusted dedicated directory in deployment.
    with sqlite3.connect(str(path), timeout=5) as conn:
        conn.execute('PRAGMA synchronous=FULL')
        conn.execute('BEGIN IMMEDIATE')
        conn.execute('CREATE TABLE IF NOT EXISTS evidence_access_log ('
                     'id INTEGER PRIMARY KEY, timestamp_ns INTEGER NOT NULL, subject_sha256 TEXT NOT NULL,'
                     'action TEXT NOT NULL, outcome TEXT NOT NULL, manifest_sha256 TEXT NOT NULL,'
                     'previous_sha256 TEXT NOT NULL, mac_sha256 TEXT NOT NULL)')
        rows = conn.execute('SELECT id,timestamp_ns,subject_sha256,action,outcome,manifest_sha256,'
                            'previous_sha256,mac_sha256 FROM evidence_access_log ORDER BY id').fetchall()
        if trusted_checkpoint_count is not None and (type(trusted_checkpoint_count) is not int or trusted_checkpoint_count < 0):
            raise ValueError('AUDIT_CHECKPOINT_INVALID')
        if trusted_checkpoint_count is not None and trusted_checkpoint_count > len(rows):
            raise ValueError('AUDIT_ROLLBACK_DETECTED')
        previous = GENESIS
        if trusted_checkpoint_count == 0 and not hmac.compare_digest(previous, trusted_audit_head or ''):
            raise ValueError('AUDIT_CHECKPOINT_MISMATCH')
        for expected_seq, (seq, ts, sub, act, out, digest, prev, mac) in enumerate(rows, 1):
            record = {'seq': seq, 'timestamp_ns': ts, 'subject_sha256': sub, 'action': act,
                      'outcome': out, 'manifest_sha256': digest, 'previous_sha256': prev}
            if seq != expected_seq or prev != previous or not hmac.compare_digest(mac, _mac(audit_key, record)):
                raise ValueError('AUDIT_CHAIN_INVALID')
            previous = hashlib.sha256(_canonical({**record, 'mac_sha256': mac})).hexdigest()
            if trusted_checkpoint_count == expected_seq and not hmac.compare_digest(previous, trusted_audit_head or ''):
                raise ValueError('AUDIT_CHECKPOINT_MISMATCH')
        if trusted_checkpoint_count is None and trusted_audit_head is not None and not hmac.compare_digest(previous, trusted_audit_head):
            raise ValueError('AUDIT_TRUSTED_HEAD_MISMATCH')
        record = {'seq': (rows[-1][0] + 1 if rows else 1), 'timestamp_ns': time.time_ns(),
                  'subject_sha256': hashlib.sha256(subject.encode()).hexdigest(),
                  'action': action, 'outcome': outcome, 'manifest_sha256': manifest_digest,
                  'previous_sha256': previous}
        mac = _mac(audit_key, record)
        conn.execute('INSERT INTO evidence_access_log(id,timestamp_ns,subject_sha256,action,outcome,'
                     'manifest_sha256,previous_sha256,mac_sha256) VALUES (?,?,?,?,?,?,?,?)',
                     (record['seq'], record['timestamp_ns'], record['subject_sha256'], action,
                      outcome, manifest_digest, previous, mac))
        head = hashlib.sha256(_canonical({**record, 'mac_sha256': mac})).hexdigest()
    return head


def serve_evidence(manifest, *, principal, manifest_keys, audit_db, audit_key,
                   representation='json', trusted_manifest_sha256=None, trusted_audit_head=None, trusted_checkpoint_count=None):
    """Return (content_type, bytes). Authentication and HTTP transport are caller-owned.

    audit_key is mandatory; successful disclosure requires a committed authenticated audit.
    The resulting audit head must be anchored externally to detect whole-file rollback.
    """
    subject = _principal(principal)
    if representation not in ('json', 'html'):
        raise ValueError('REPRESENTATION_INVALID')
    status = cockpit_status(manifest, manifest_keys=manifest_keys,
                            trusted_manifest_sha256=trusted_manifest_sha256)
    if representation == 'html':
        content = cockpit_panel(manifest, manifest_keys=manifest_keys,
                                trusted_manifest_sha256=trusted_manifest_sha256).encode('utf-8')
        mime = 'text/html; charset=utf-8'
    else:
        content = json.dumps(status, sort_keys=True).encode('utf-8')
        mime = 'application/json; charset=utf-8'
    _audit(audit_db, subject, 'evidence.read.' + representation, 'ALLOW',
           status['manifest_sha256'], audit_key, trusted_audit_head=trusted_audit_head,
           trusted_checkpoint_count=trusted_checkpoint_count)
    return mime, content
