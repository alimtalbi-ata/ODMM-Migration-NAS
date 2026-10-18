"""V190.9: independent segmented audit with explicit dual-key boundary.

Keys are caller-supplied; this does not rekey the legacy orphan audit chain.
All mutations require a caller-managed SQLite transaction for coupling to decisions.
"""
import hashlib
import hmac
import json
from native_migration_errors import MigrationBlocked


def enc(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def keycheck(key):
    if not isinstance(key, bytes) or len(key) < 32:
        raise MigrationBlocked('SEGMENT_KEY_INVALID')
    return key


def mac(key, payload):
    return hmac.new(keycheck(key), enc(payload), hashlib.sha256).hexdigest()


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS audit_segments (
        segment INTEGER PRIMARY KEY, key_id TEXT NOT NULL, predecessor TEXT NOT NULL,
        boundary_old_mac TEXT, boundary_new_mac TEXT, head TEXT NOT NULL, count INTEGER NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS audit_segment_events (
        segment INTEGER NOT NULL, seq INTEGER NOT NULL, event TEXT NOT NULL, mac TEXT NOT NULL,
        PRIMARY KEY(segment,seq), FOREIGN KEY(segment) REFERENCES audit_segments(segment))''')


def _segments(db):
    return db.execute('SELECT segment,key_id,predecessor,boundary_old_mac,boundary_new_mac,head,count FROM audit_segments ORDER BY segment').fetchall()


def verify(db, keys, *, trusted_anchor=None):
    initialize(db)
    rows = _segments(db)
    prior = '0' * 64
    prior_id = None
    total = 0
    for expected_number, (number, key_id, predecessor, old_mac, new_mac, head, count) in enumerate(rows, 1):
        if number != expected_number or key_id not in keys or predecessor != prior or not isinstance(count,int) or count < 0:
            raise MigrationBlocked('SEGMENT_CHAIN_INVALID')
        key = keycheck(keys[key_id])
        if number == 1:
            if old_mac is not None or new_mac is not None:
                raise MigrationBlocked('SEGMENT_BOUNDARY_INVALID')
        else:
            boundary = {'segment':number,'previous_head':prior,'previous_key_id':prior_id,'new_key_id':key_id}
            if prior_id not in keys or old_mac != mac(keys[prior_id], boundary) or new_mac != mac(key, boundary):
                raise MigrationBlocked('SEGMENT_BOUNDARY_INVALID')
        prev = predecessor
        events = db.execute('SELECT seq,event,mac FROM audit_segment_events WHERE segment=? ORDER BY seq', (number,)).fetchall()
        if len(events) != count:
            raise MigrationBlocked('SEGMENT_COUNT_INVALID')
        for i, (seq, event, digest) in enumerate(events, 1):
            if seq != i or digest != mac(key, {'segment':number,'seq':i,'previous':prev,'event':event}):
                raise MigrationBlocked('SEGMENT_EVENT_INVALID')
            prev = digest
        if head != prev:
            raise MigrationBlocked('SEGMENT_HEAD_INVALID')
        prior, prior_id = head, key_id
        total += count
    if trusted_anchor is not None:
        anchor = trusted_anchor
        if not isinstance(anchor,dict) or anchor.get('segment') != len(rows) or anchor.get('head') != prior or anchor.get('events') != total:
            raise MigrationBlocked('SEGMENT_ANCHOR_MISMATCH')
    return {'segments':len(rows),'events':total,'head':prior,'cutover_authorized':False}


def start(db, key_id, key):
    initialize(db)
    if _segments(db):
        raise MigrationBlocked('SEGMENT_ALREADY_STARTED')
    if not isinstance(key_id,str) or not key_id.strip():
        raise MigrationBlocked('SEGMENT_KEY_ID_INVALID')
    keycheck(key)
    db.execute('INSERT INTO audit_segments VALUES(1,?,?,NULL,NULL,?,0)',(key_id,'0'*64,'0'*64))


def append(db, keys, event):
    verify(db, keys)
    row = db.execute('SELECT segment,key_id,head,count FROM audit_segments ORDER BY segment DESC LIMIT 1').fetchone()
    if row is None:
        raise MigrationBlocked('SEGMENT_NOT_STARTED')
    number, key_id, prev, count = row
    event_json = enc(event).decode()
    digest = mac(keys[key_id], {'segment':number,'seq':count+1,'previous':prev,'event':event_json})
    db.execute('INSERT INTO audit_segment_events VALUES(?,?,?,?)',(number,count+1,event_json,digest))
    if db.execute('UPDATE audit_segments SET head=?,count=? WHERE segment=? AND head=? AND count=?',
                  (digest,count+1,number,prev,count)).rowcount != 1:
        raise MigrationBlocked('SEGMENT_CONCURRENT_CHANGE')
    return digest


def rotate(db, keys, new_key_id, new_key):
    """Caller MUST wrap this and preceding/following decisions in BEGIN IMMEDIATE/COMMIT.
    Explicit rotation; never changes or erases old segments."""
    summary = verify(db, keys)
    row = db.execute('SELECT segment,key_id,head FROM audit_segments ORDER BY segment DESC LIMIT 1').fetchone()
    if row is None:
        raise MigrationBlocked('SEGMENT_NOT_STARTED')
    number, old_id, previous = row
    if not isinstance(new_key_id,str) or not new_key_id.strip() or new_key_id in keys:
        raise MigrationBlocked('SEGMENT_KEY_ID_INVALID')
    if any(hmac.compare_digest(keycheck(k),keycheck(new_key)) for k in keys.values()):
        raise MigrationBlocked('SEGMENT_KEYS_IDENTICAL')
    boundary = {'segment':number+1,'previous_head':previous,'previous_key_id':old_id,'new_key_id':new_key_id}
    db.execute('INSERT INTO audit_segments VALUES(?,?,?,?,?,?,0)',
               (number+1,new_key_id,previous,mac(keys[old_id],boundary),mac(new_key,boundary),previous))
    return {'segments':summary['segments']+1,'new_key_id':new_key_id,'rotation_applied':True,'cutover_authorized':False}


def anchor(db, keys):
    result = verify(db, keys)
    return {'segment':result['segments'],'events':result['events'],'head':result['head']}
