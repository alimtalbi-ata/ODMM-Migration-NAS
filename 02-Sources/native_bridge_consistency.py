"""V191.1 read-only cross-ledger reconciliation. Use a trusted external anchor to detect tail truncation."""
import json
from native_migration_errors import MigrationBlocked
from native_orphan_audit import verify as legacy_verify
from native_segmented_audit import verify as segment_verify, mac


def verify_bridge(db, *, legacy_key, segment_keys, trusted_legacy=None, trusted_segment=None):
    """Validate 1:1 ordered correspondence between post-activation legacy and segmented decisions.

    Caller should hold a consistent SQLite read transaction when concurrent writers exist.
    """
    state = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_bridge_state'").fetchone()
    if not state:
        raise MigrationBlocked('BRIDGE_NOT_ACTIVE')
    state = db.execute('SELECT legacy_events,legacy_head,initial_key_id,activation_mac FROM audit_bridge_state WHERE id=1').fetchone()
    if not state:
        raise MigrationBlocked('BRIDGE_NOT_ACTIVE')
    legacy = legacy_verify(db, legacy_key)
    segments = segment_verify(db, segment_keys, trusted_anchor=trusted_segment)
    if trusted_legacy is not None and (legacy['events'] != trusted_legacy.get('events') or legacy['head'] != trusted_legacy.get('head')):
        raise MigrationBlocked('BRIDGE_LEGACY_ANCHOR_MISMATCH')
    initial_count, initial_head, key_id, signature = state
    if key_id not in segment_keys or initial_count > legacy['events']:
        raise MigrationBlocked('BRIDGE_CHECKPOINT_INVALID')
    events = db.execute('SELECT segment,seq,event FROM audit_segment_events ORDER BY segment,seq').fetchall()
    if not events or (events[0][0],events[0][1]) != (1,1):
        raise MigrationBlocked('BRIDGE_CHECKPOINT_MISSING')
    checkpoint = json.loads(events[0][2])
    if (checkpoint.get('kind') != 'LEGACY_AUDIT_CHECKPOINT' or
        checkpoint.get('legacy_events') != initial_count or
        checkpoint.get('legacy_head') != initial_head or
        mac(segment_keys[key_id],checkpoint) != signature):
        raise MigrationBlocked('BRIDGE_CHECKPOINT_INVALID')
    rows = db.execute('SELECT seq,previous_mac,event_json,mac FROM orphan_audit_chain ORDER BY seq').fetchall()
    if initial_count:
        if rows[initial_count-1][3] != initial_head:
            raise MigrationBlocked('BRIDGE_LEGACY_PREFIX_CHANGED')
    elif initial_head != '0'*64:
        raise MigrationBlocked('BRIDGE_LEGACY_PREFIX_CHANGED')
    post = rows[initial_count:]
    if len(events)-1 != len(post) or segments['events'] != len(events):
        raise MigrationBlocked('BRIDGE_DECISION_COUNT_MISMATCH')
    for (_,_,serialized), (seq,_,legacy_json,head) in zip(events[1:],post):
        event = json.loads(serialized)
        decision = event.get('decision')
        original = json.loads(legacy_json)
        if (event.get('kind') != 'ORPHAN_REVIEW_DECISION' or
            event.get('legacy_sequence') != seq or event.get('legacy_head') != head or
            not isinstance(decision,dict) or
            any(decision.get(k) != original.get(k) for k in ('review_id','path','operator','rationale')) or
            original.get('kind') != 'MANUAL_INVESTIGATION_ONLY'):
            raise MigrationBlocked('BRIDGE_DECISION_DIVERGENCE')
    return {'status':'CONSISTENT','linked_decisions':len(post),'legacy_events':legacy['events'],
            'segment_events':segments['events'],'cutover_authorized':False}


def verify_bridge_snapshot(database_path, *, legacy_key, segment_keys,
                           trusted_legacy=None, trusted_segment=None):
    """Read both audit chains from one WAL snapshot on an independent connection.

    A separate connection avoids accidentally inheriting a writer's uncommitted
    changes and makes the snapshot lifetime explicit. This is read-only and
    never creates or modifies a database.
    """
    import sqlite3
    from pathlib import Path
    path = Path(database_path)
    if not path.is_file():
        raise MigrationBlocked('BRIDGE_DATABASE_MISSING')
    # SQLite URI mode=ro guarantees that the verification cannot write.
    uri = path.resolve().as_uri() + '?mode=ro'
    db = sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        try:
            result = verify_bridge(db, legacy_key=legacy_key,
                                   segment_keys=segment_keys,
                                   trusted_legacy=trusted_legacy,
                                   trusted_segment=trusted_segment)
            db.execute('COMMIT')
            return result
        except BaseException:
            db.execute('ROLLBACK')
            raise
    finally:
        db.close()
