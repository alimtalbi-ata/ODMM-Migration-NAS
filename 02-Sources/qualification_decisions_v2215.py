"""Append-only human review decisions bound to ODMM dossier digest.

HMAC authenticates records to holders of the configured secret; it is not a
public-key signature or proof of an individual's identity.
Author: Abdelhalim Talbi.
"""
import hashlib
import hmac
import json
import sqlite3
import time
from pathlib import Path
from qualification_dossier_v2214 import canonical_bytes, verify_dossier

SCHEMA = 'odmm.qualification.review.v2215'
ACTIONS = frozenset({'APPROVE_REVIEW', 'REJECT_REVIEW', 'REVOKE_REVIEW'})


def _key(secret):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError('HMAC_KEY_MINIMUM_32_BYTES')
    return secret


def _mac(payload, secret):
    return hmac.new(_key(secret), b'ODMM-REVIEW-V2215\0' + canonical_bytes(payload), hashlib.sha256).hexdigest()


def _connect(path):
    if not path:
        raise ValueError('DB_PATH_REQUIRED')
    con = sqlite3.connect(str(path), timeout=15, isolation_level=None)
    con.execute('PRAGMA busy_timeout=15000')
    con.execute('CREATE TABLE IF NOT EXISTS review_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, dossier_sha256 TEXT NOT NULL, event_json TEXT NOT NULL, mac TEXT NOT NULL, prev_mac TEXT NOT NULL)')
    return con


def append_review(path, dossier, *, action, reviewer, reason, secret, timestamp=None, request_id=None):
    """Commit a chained decision; never grants cutover. Revocation requires an active approval."""
    _key(secret)
    if not verify_dossier(dossier):
        raise ValueError('INVALID_DOSSIER')
    if action not in ACTIONS or not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 128:
        raise ValueError('INVALID_REVIEWER_OR_ACTION')
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2048:
        raise ValueError('REASON_REQUIRED')
    if request_id is not None and (not isinstance(request_id, str) or not (8 <= len(request_id) <= 128) or not all(c.isascii() and (c.isalnum() or c in '-_') for c in request_id)):
        raise ValueError('INVALID_REQUEST_ID')
    digest = dossier['payload_sha256']
    con = _connect(path)
    try:
        con.execute('BEGIN IMMEDIATE')
        history = _read_verified(con, secret)
        if request_id is not None:
            matches = [e for e in history if e.get('request_id') == request_id]
            if matches:
                old = matches[0]
                if (old['dossier_sha256'], old['action'], old['reviewer'], old['reason']) != (digest, action, reviewer.strip(), reason.strip()):
                    raise ValueError('REQUEST_ID_REUSED_WITH_DIFFERENT_PAYLOAD')
                return {**old, 'authentication': 'HMAC-SHA256_SHARED_KEY', 'idempotent_replay': True}
        own = [e for e in history if e['dossier_sha256'] == digest]
        active = bool(own and own[-1]['action'] == 'APPROVE_REVIEW')
        if action == 'REVOKE_REVIEW' and not active:
            raise ValueError('NO_ACTIVE_APPROVAL')
        if action == 'APPROVE_REVIEW' and active:
            raise ValueError('ALREADY_APPROVED')
        if action == 'REJECT_REVIEW' and active:
            raise ValueError('REVOKE_BEFORE_REJECT')
        seq = len(history) + 1
        prev = history[-1]['mac'] if history else 'GENESIS'
        event = {'schema': SCHEMA, 'seq': seq, 'dossier_sha256': digest, 'action': action,
                 'reviewer': reviewer.strip(), 'reason': reason.strip(),
                 'timestamp': int(time.time()) if timestamp is None else timestamp,
                 'prev_mac': prev, 'cutover_authorized': False}
        if type(event['timestamp']) is not int or event['timestamp'] < 0:
            raise ValueError('INVALID_TIMESTAMP')
        if request_id is not None:
            event['request_id'] = request_id
        mac = _mac(event, secret)
        con.execute('INSERT INTO review_events(seq,dossier_sha256,event_json,mac,prev_mac) VALUES (?,?,?,?,?)',
                    (seq, digest, canonical_bytes(event).decode(), mac, prev))
        con.commit()
        return {**event, 'mac': mac, 'authentication': 'HMAC-SHA256_SHARED_KEY'}
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def _read_verified(con, secret):
    rows = con.execute('SELECT seq,dossier_sha256,event_json,mac,prev_mac FROM review_events ORDER BY seq').fetchall()
    prev = 'GENESIS'
    result = []
    for expected, (seq, digest, raw, mac, stored_prev) in enumerate(rows, 1):
        try:
            event = json.loads(raw)
            valid = (seq == expected and event['schema'] == SCHEMA and event['seq'] == seq
                     and event['dossier_sha256'] == digest and event['prev_mac'] == prev
                     and stored_prev == prev and event['action'] in ACTIONS
                     and event['cutover_authorized'] is False
                     and hmac.compare_digest(_mac(event, secret), mac))
        except (ValueError, TypeError, KeyError):
            valid = False
        if not valid:
            raise ValueError('REVIEW_CHAIN_INTEGRITY_FAILURE')
        result.append({**event, 'mac': mac})
        prev = mac
    return result


def review_status(path, dossier, *, secret):
    _key(secret)
    if not verify_dossier(dossier):
        raise ValueError('INVALID_DOSSIER')
    con = _connect(path)
    try:
        events = [e for e in _read_verified(con, secret) if e['dossier_sha256'] == dossier['payload_sha256']]
    finally:
        con.close()
    last = events[-1] if events else None
    return {'dossier_sha256': dossier['payload_sha256'], 'events': events,
            'review_status': ('APPROVED_REVIEW_ONLY' if last and last['action'] == 'APPROVE_REVIEW'
                              else 'REVOKED' if last and last['action'] == 'REVOKE_REVIEW'
                              else 'REJECTED' if last and last['action'] == 'REJECT_REVIEW'
                              else 'PENDING_HUMAN_REVIEW'),
            'cutover_authorized': False, 'windows_qualified': False, 'nas_qualified': False,
            'signature_type': 'HMAC_SHARED_KEY_NOT_PERSONAL_SIGNATURE'}
