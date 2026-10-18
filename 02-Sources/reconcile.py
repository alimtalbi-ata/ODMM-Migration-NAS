"""Read-only recovery classification for ODMM local staging.
Never mutates external files or automatically replays writes.
"""
import hashlib
import os
from pathlib import Path
from chunked import ChunkedRegistry


def digest_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


class ReconciliationRegistry(ChunkedRegistry):
    def classify_recovery(self, intent_id):
        intent = self.db.execute('SELECT * FROM write_intents WHERE intent_id=?', (intent_id,)).fetchone()
        session = self.db.execute('SELECT * FROM chunk_sessions WHERE intent_id=?', (intent_id,)).fetchone()
        if intent is None or session is None:
            raise KeyError(intent_id)
        target, stage = Path(intent['target_path']), Path(session['stage_path'])
        expected = intent['expected_sha256']
        result = {'intent_id': intent_id, 'intent_state': intent['state'],
                  'session_state': session['state'], 'automatic_replay_allowed': False}
        if target.is_symlink() or stage.is_symlink():
            result['classification'] = 'UNSAFE_PATH'
        elif target.exists():
            if not target.is_file():
                result['classification'] = 'TARGET_NOT_REGULAR'
            elif target.stat().st_size == session['total_bytes'] and digest_file(target) == expected:
                result['classification'] = ('PUBLISHED_CONFIRMED' if intent['state'] == 'VERIFIED'
                                            and session['state'] == 'PUBLISHED' else 'PUBLISHED_UNACKNOWLEDGED')
            else:
                result['classification'] = 'TARGET_CONFLICT'
        elif not stage.exists():
            result['classification'] = 'STAGE_MISSING'
        elif not stage.is_file():
            result['classification'] = 'UNSAFE_STAGE'
        else:
            evidence = self.inspect_chunks(intent_id)
            result['chunks'] = evidence
            if evidence['invalid_offsets']:
                result['classification'] = 'STAGE_CORRUPT'
            elif evidence['complete'] and stage.stat().st_size == session['total_bytes'] and digest_file(stage) == expected:
                result['classification'] = 'STAGE_COMPLETE_UNPUBLISHED'
            elif evidence['complete']:
                result['classification'] = 'STAGE_WHOLE_HASH_MISMATCH'
            else:
                result['classification'] = 'STAGE_PARTIAL'
        return result


def probe_local_capabilities(directory):
    """Conservative capability report; no assumption of NFS/SMB durability."""
    p = Path(directory)
    if not p.is_dir() or p.is_symlink():
        raise ValueError('UNSAFE_DIRECTORY')
    return {'directory': str(p.resolve()), 'platform': os.name,
            'local_posix_staging_supported': os.name == 'posix',
            'nfs_durability_qualified': False, 'smb_durability_qualified': False,
            'windows_atomic_publication_qualified': False,
            'distributed_fencing_qualified': False,
            'status': 'UNQUALIFIED_FOR_REMOTE_NAS'}
