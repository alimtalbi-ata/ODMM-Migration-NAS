"""Append-only HMAC chained evidence for orphan review; key supplied externally.

Not a remote transparency log: DB administrators can truncate the tail.
"""
import hashlib
import hmac
import json
import time
from native_migration_errors import MigrationBlocked


def _encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _key(key):
    if not isinstance(key, bytes) or len(key) < 32:
        raise MigrationBlocked('AUDIT_KEY_REQUIRED_32_BYTES')
    return key


def initialize(db):
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='orphan_audit_chain'").fetchone():
        return
    db.execute('''CREATE TABLE IF NOT EXISTS orphan_audit_chain (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        previous_mac TEXT NOT NULL, event_json TEXT NOT NULL,
        mac TEXT NOT NULL)''')


def verify(db, key):
    key = _key(key)
    initialize(db)
    prev = '0' * 64
    count = 0
    for seq, previous, event_json, mac in db.execute(
        'SELECT seq,previous_mac,event_json,mac FROM orphan_audit_chain ORDER BY seq'
    ):
        if seq != count + 1 or previous != prev:
            raise MigrationBlocked('AUDIT_CHAIN_BROKEN')
        expected = hmac.new(key, _encode({'seq':seq,'previous':prev,'event':event_json}), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            raise MigrationBlocked('AUDIT_MAC_INVALID')
        prev = mac
        count += 1
    return {'status':'VERIFIED', 'events':count, 'head':prev}


def append(db, key, *, kind, review_id, path, operator, rationale):
    key = _key(key)
    result = verify(db, key)
    seq = result['events'] + 1
    event = _encode({'kind':kind,'review_id':review_id,'path':path,
                     'operator':operator,'rationale':rationale,'timestamp_ns':time.time_ns()}).decode()
    prev = result['head']
    mac = hmac.new(key, _encode({'seq':seq,'previous':prev,'event':event}), hashlib.sha256).hexdigest()
    db.execute('INSERT INTO orphan_audit_chain(seq,previous_mac,event_json,mac) VALUES(?,?,?,?)',
               (seq,prev,event,mac))
    return {'sequence':seq,'mac':mac}
