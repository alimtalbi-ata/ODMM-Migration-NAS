"""Opt-in transactional bridge from legacy orphan audit to segmented audit.

Activation checkpoints the existing legacy chain, never imports/re-signs historical events.
All subsequent review decisions dual-write within the caller's SQLite transaction.
"""
import json
from native_migration_errors import MigrationBlocked
from native_orphan_audit import verify as legacy_verify
from native_segmented_audit import initialize, start, append, verify, mac


def _schema(db):
    db.execute('''CREATE TABLE IF NOT EXISTS audit_bridge_state (
      id INTEGER PRIMARY KEY CHECK(id=1), legacy_events INTEGER NOT NULL,
      legacy_head TEXT NOT NULL, initial_key_id TEXT NOT NULL,
      activation_mac TEXT NOT NULL)''')


def activate(engine, *, legacy_key, segment_key_id, segment_key, operator, rationale):
    if not operator or not operator.strip() or not rationale or len(rationale.strip()) < 10:
        raise MigrationBlocked('BRIDGE_APPROVAL_REQUIRED')
    with engine._exclusive():
        engine._check_roots()
        engine.db.execute('BEGIN IMMEDIATE')
        try:
            _schema(engine.db)
            if engine.db.execute('SELECT 1 FROM audit_bridge_state').fetchone():
                raise MigrationBlocked('BRIDGE_ALREADY_ACTIVE')
            legacy = legacy_verify(engine.db, legacy_key)
            initialize(engine.db)
            if verify(engine.db, {})['segments']:
                raise MigrationBlocked('BRIDGE_SEGMENTS_ALREADY_EXIST')
            start(engine.db, segment_key_id, segment_key)
            checkpoint = {'kind':'LEGACY_AUDIT_CHECKPOINT','legacy_events':legacy['events'],
                          'legacy_head':legacy['head'],'operator':operator,'rationale':rationale}
            keys = {segment_key_id:segment_key}
            append(engine.db, keys, checkpoint)
            signature = mac(segment_key, checkpoint)
            engine.db.execute('INSERT INTO audit_bridge_state VALUES(1,?,?,?,?)',
                              (legacy['events'],legacy['head'],segment_key_id,signature))
            engine.db.execute('COMMIT')
        except BaseException:
            engine.db.execute('ROLLBACK')
            raise
    return {'status':'BRIDGE_ACTIVE','legacy_checkpoint':legacy,'cutover_authorized':False}


def append_decision(db, *, legacy_key, segment_keys, event):
    """Call only inside BEGIN IMMEDIATE after legacy event append, before COMMIT."""
    _schema(db)
    state = db.execute('SELECT legacy_events,legacy_head,initial_key_id,activation_mac FROM audit_bridge_state WHERE id=1').fetchone()
    if not state:
        return None
    legacy = legacy_verify(db, legacy_key)
    if legacy['events'] <= state[0]:
        raise MigrationBlocked('BRIDGE_LEGACY_CHAIN_REWOUND')
    result = verify(db, segment_keys)
    if not result['segments']:
        raise MigrationBlocked('BRIDGE_SEGMENTS_MISSING')
    first = db.execute('SELECT event FROM audit_segment_events WHERE segment=1 AND seq=1').fetchone()
    if not first:
        raise MigrationBlocked('BRIDGE_CHECKPOINT_MISSING')
    checkpoint = json.loads(first[0])
    if (checkpoint.get('kind') != 'LEGACY_AUDIT_CHECKPOINT' or
        checkpoint.get('legacy_events') != state[0] or checkpoint.get('legacy_head') != state[1] or
        state[2] not in segment_keys or mac(segment_keys[state[2]], checkpoint) != state[3]):
        raise MigrationBlocked('BRIDGE_CHECKPOINT_INVALID')
    return append(db, segment_keys, {'kind':'ORPHAN_REVIEW_DECISION',
                                    'legacy_sequence':legacy['events'],'legacy_head':legacy['head'],
                                    'decision':event})
