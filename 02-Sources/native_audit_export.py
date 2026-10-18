"""Portable HMAC evidence bundle and independently retained head checkpoint.

Exports do not transmit data. The operator MUST store the checkpoint outside the
migration host; same-host export does not protect against privileged rewriting.
"""
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from native_orphan_audit import verify, initialize, _key, _encode
from native_migration_errors import MigrationBlocked

FORMAT = 'ODMM-ORPHAN-AUDIT-EXPORT-V1'

def build_bundle(db, key):
    """Consistent read of head and events, including concurrent WAL writers.

    SAVEPOINT supports callers already in a transaction. The first SELECT pins
    the SQLite read snapshot; no external key material is persisted.
    """
    key = _key(key)
    initialize(db)
    db.execute('SAVEPOINT odmm_audit_export_snapshot')
    try:
        # A SELECT pins the snapshot before verification and materialization.
        events = [dict(seq=seq, previous_mac=previous, event_json=event, mac=mac)
                  for seq, previous, event, mac in db.execute(
                      'SELECT seq,previous_mac,event_json,mac FROM orphan_audit_chain ORDER BY seq')]
        summary = verify(db, key)
        if len(events) != summary['events'] or (events[-1]['mac'] if events else '0'*64) != summary['head']:
            raise MigrationBlocked('AUDIT_EXPORT_SNAPSHOT_CONFLICT')
        payload = {'format': FORMAT, 'events': events, 'count': summary['events'], 'head': summary['head']}
        signature = hmac.new(key, _encode(payload), hashlib.sha256).hexdigest()
        return {'payload': payload, 'signature': signature, 'algorithm': 'HMAC-SHA256'}
    finally:
        db.execute('ROLLBACK TO SAVEPOINT odmm_audit_export_snapshot')
        db.execute('RELEASE SAVEPOINT odmm_audit_export_snapshot')

def verify_bundle(bundle, key, *, trusted_checkpoint=None):
    key = _key(key)
    if not isinstance(bundle, dict) or bundle.get('algorithm') != 'HMAC-SHA256':
        raise MigrationBlocked('AUDIT_EXPORT_FORMAT_INVALID')
    payload = bundle.get('payload')
    if not isinstance(payload, dict) or payload.get('format') != FORMAT:
        raise MigrationBlocked('AUDIT_EXPORT_FORMAT_INVALID')
    expected = hmac.new(key, _encode(payload), hashlib.sha256).hexdigest()
    if not isinstance(bundle.get('signature'), str) or not hmac.compare_digest(expected, bundle['signature']):
        raise MigrationBlocked('AUDIT_EXPORT_SIGNATURE_INVALID')
    events = payload.get('events')
    if not isinstance(events, list) or payload.get('count') != len(events):
        raise MigrationBlocked('AUDIT_EXPORT_COUNT_INVALID')
    prev = '0' * 64
    for index, row in enumerate(events, 1):
        if not isinstance(row, dict) or set(row) != {'seq','previous_mac','event_json','mac'}:
            raise MigrationBlocked('AUDIT_EXPORT_EVENT_INVALID')
        if row['seq'] != index or row['previous_mac'] != prev or not isinstance(row['event_json'], str):
            raise MigrationBlocked('AUDIT_EXPORT_CHAIN_BROKEN')
        mac = hmac.new(key, _encode({'seq':index,'previous':prev,'event':row['event_json']}), hashlib.sha256).hexdigest()
        if not isinstance(row['mac'], str) or not hmac.compare_digest(mac, row['mac']):
            raise MigrationBlocked('AUDIT_EXPORT_MAC_INVALID')
        prev = mac
    if payload.get('head') != prev:
        raise MigrationBlocked('AUDIT_EXPORT_HEAD_INVALID')
    if trusted_checkpoint is not None:
        cp = verify_checkpoint(trusted_checkpoint, key)
        if len(events) < cp['count'] or (cp['count'] and events[cp['count'] - 1]['mac'] != cp['head']):
            raise MigrationBlocked('AUDIT_EXPORT_ROLLBACK_OR_FORK')
    return {'status':'VERIFIED','events':len(events),'head':prev,'cutover_authorized':False}

def checkpoint(bundle, key):
    summary = verify_bundle(bundle, key)
    payload = {'format':'ODMM-ORPHAN-AUDIT-CHECKPOINT-V1', 'count':summary['events'],'head':summary['head']}
    return {'payload':payload, 'signature':hmac.new(_key(key), _encode(payload), hashlib.sha256).hexdigest()}

def verify_checkpoint(cp, key):
    if not isinstance(cp, dict) or not isinstance(cp.get('payload'),dict):
        raise MigrationBlocked('AUDIT_CHECKPOINT_INVALID')
    payload = cp['payload']
    expected = hmac.new(_key(key),_encode(payload),hashlib.sha256).hexdigest()
    if (payload.get('format') != 'ODMM-ORPHAN-AUDIT-CHECKPOINT-V1'
        or not isinstance(payload.get('count'),int) or isinstance(payload.get('count'),bool)
        or payload['count'] < 0 or not isinstance(payload.get('head'),str)
        or not isinstance(cp.get('signature'),str)
        or not hmac.compare_digest(expected,cp['signature'])):
        raise MigrationBlocked('AUDIT_CHECKPOINT_INVALID')
    return payload

def export_file(db, key, destination):
    """Atomic local export; never overwrites existing evidence."""
    bundle = build_bundle(db, key)
    verify_bundle(bundle, key)
    destination = Path(destination)
    if destination.is_symlink() or destination.exists():
        raise MigrationBlocked('AUDIT_EXPORT_EXISTS')
    fd, tmp = tempfile.mkstemp(prefix='.odmm-audit-', dir=str(destination.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(_encode(bundle) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(tmp, destination, follow_symlinks=False)
        except FileExistsError:
            raise MigrationBlocked('AUDIT_EXPORT_EXISTS')
        dirfd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(dirfd)
        finally: os.close(dirfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return {'path':str(destination),'checkpoint':checkpoint(bundle,key),'events':bundle['payload']['count']}

ROTATION_FORMAT = 'ODMM-AUDIT-KEY-ROTATION-V1'

def rotation_attestation(previous_checkpoint, old_key, new_key, *, old_key_id, new_key_id):
    """Dual-key authorization evidence; does NOT switch database key in place."""
    old_key, new_key = _key(old_key), _key(new_key)
    verify_checkpoint(previous_checkpoint, old_key)
    if not all(isinstance(x, str) and x.strip() for x in (old_key_id, new_key_id)) or old_key_id == new_key_id:
        raise MigrationBlocked('AUDIT_ROTATION_KEY_IDS_INVALID')
    if hmac.compare_digest(old_key, new_key):
        raise MigrationBlocked('AUDIT_ROTATION_KEYS_IDENTICAL')
    payload = {'format': ROTATION_FORMAT, 'previous_checkpoint': previous_checkpoint,
               'old_key_id': old_key_id, 'new_key_id': new_key_id}
    return {'payload': payload,
            'old_signature': hmac.new(old_key, _encode(payload), hashlib.sha256).hexdigest(),
            'new_signature': hmac.new(new_key, _encode(payload), hashlib.sha256).hexdigest(),
            'rotation_applied': False, 'cutover_authorized': False}

def verify_rotation_attestation(attestation, old_key, new_key):
    if not isinstance(attestation, dict) or not isinstance(attestation.get('payload'), dict):
        raise MigrationBlocked('AUDIT_ROTATION_INVALID')
    payload = attestation['payload']
    if payload.get('format') != ROTATION_FORMAT or attestation.get('rotation_applied') is not False:
        raise MigrationBlocked('AUDIT_ROTATION_INVALID')
    if not isinstance(payload.get('old_key_id'), str) or not isinstance(payload.get('new_key_id'), str) or not payload['old_key_id'].strip() or not payload['new_key_id'].strip() or payload['old_key_id'] == payload['new_key_id']:
        raise MigrationBlocked('AUDIT_ROTATION_KEY_IDS_INVALID')
    verify_checkpoint(payload.get('previous_checkpoint'), old_key)
    if hmac.compare_digest(_key(old_key), _key(new_key)):
        raise MigrationBlocked('AUDIT_ROTATION_KEYS_IDENTICAL')
    for field, key in (('old_signature', old_key), ('new_signature', new_key)):
        expected = hmac.new(_key(key), _encode(payload), hashlib.sha256).hexdigest()
        if not isinstance(attestation.get(field), str) or not hmac.compare_digest(attestation[field], expected):
            raise MigrationBlocked('AUDIT_ROTATION_SIGNATURE_INVALID')
    return {'status':'DUAL_SIGNATURE_VERIFIED', 'rotation_applied':False, 'cutover_authorized':False}
