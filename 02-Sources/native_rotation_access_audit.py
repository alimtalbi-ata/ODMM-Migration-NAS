"""V195.3 durable, fail-closed, chained access decision audit (SQLite)."""
import hashlib
import hmac
import json
import os
import sqlite3
import time
from pathlib import Path


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(key, obj):
    return hmac.new(key, canonical(obj), hashlib.sha256).hexdigest()


def _connect(path):
    db = sqlite3.connect(str(path), timeout=10, isolation_level=None)
    db.execute('PRAGMA busy_timeout=10000')
    db.execute('PRAGMA synchronous=FULL')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('CREATE TABLE IF NOT EXISTS access_audit (seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, previous TEXT NOT NULL, signature TEXT NOT NULL)')
    return db


def verify_rows(rows, key, expected_head=None):
    previous = 'GENESIS'
    for i, (seq, event_id, payload, prev, signature) in enumerate(rows, 1):
        if seq != i or prev != previous:
            raise ValueError('AUDIT_CHAIN_BROKEN')
        try:
            record = json.loads(payload)
        except (TypeError, ValueError):
            raise ValueError('AUDIT_PAYLOAD_INVALID') from None
        if not isinstance(record, dict) or record.get('event_id') != event_id or canonical(record).decode() != payload:
            raise ValueError('AUDIT_PAYLOAD_INVALID')
        expected = digest(key, {'seq':seq,'payload':payload,'previous':prev})
        if not hmac.compare_digest(expected, signature):
            raise ValueError('AUDIT_SIGNATURE_INVALID')
        previous = signature
    if expected_head is not None and not hmac.compare_digest(previous, expected_head):
        raise ValueError('AUDIT_HEAD_MISMATCH')
    return {'count':len(rows), 'head':previous}


class AccessAudit:
    def __init__(self, path, *, key, expected_head=None):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError('AUDIT_KEY_REQUIRED')
        self.path = Path(path)
        if not self.path.parent.is_dir() or self.path.is_symlink():
            raise ValueError('AUDIT_PATH_INVALID')
        self.key = key
        self.expected_head = expected_head

    def _rows(self, db):
        return db.execute('SELECT seq,event_id,payload,previous,signature FROM access_audit ORDER BY seq').fetchall()

    def verify(self, *, expected_head=None):
        with _connect(self.path) as db:
            return verify_rows(self._rows(db), self.key, expected_head=expected_head)

    def append(self, event):
        if not isinstance(event, dict) or not isinstance(event.get('event_id'), str) or not (1 <= len(event['event_id']) <= 128):
            raise ValueError('AUDIT_EVENT_ID_REQUIRED')
        if event.get('event') not in ('rotation_access_denied','rotation_access_allowed'):
            raise ValueError('AUDIT_EVENT_INVALID')
        payload = canonical(event).decode()
        with _connect(self.path) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                rows = self._rows(db)
                state = verify_rows(rows, self.key, expected_head=self.expected_head)
                found = db.execute('SELECT payload FROM access_audit WHERE event_id=?', (event['event_id'],)).fetchone()
                if found:
                    if found[0] != payload:
                        raise ValueError('AUDIT_DUPLICATE_CONFLICT')
                    db.execute('COMMIT')
                    return {'duplicate':True, **state}
                seq = state['count'] + 1
                sig = digest(self.key, {'seq':seq,'payload':payload,'previous':state['head']})
                db.execute('INSERT INTO access_audit VALUES (?,?,?,?,?)', (seq,event['event_id'],payload,state['head'],sig))
                db.execute('COMMIT')
                self.expected_head = sig
                return {'duplicate':False,'count':seq,'head':sig}
            except BaseException:
                db.execute('ROLLBACK')
                raise

    def export_verified(self):
        with _connect(self.path) as db:
            rows = self._rows(db)
            state = verify_rows(rows, self.key, expected_head=self.expected_head)
            return {'schema':'odmm.access-audit.v1', **state,
                    'events':[json.loads(row[2]) for row in rows],
                    'signatures':[row[4] for row in rows]}


def make_denial_sink(audit, *, id_factory=None):
    """Adapter for V195.1 denial_audit callback. Caller must protect its signing key."""
    if id_factory is None:
        import uuid
        id_factory = lambda: uuid.uuid4().hex
    def sink(record):
        audit.append({'event_id':id_factory(), **record})
    return sink
