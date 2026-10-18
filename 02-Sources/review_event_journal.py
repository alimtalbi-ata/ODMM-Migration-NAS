"""Append-only, hash-chained review event journal (tamper-evident, not authenticated)."""
import hashlib
import json
import sqlite3
import time

class JournalError(ValueError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def event_hash(previous, event):
    return hashlib.sha256((previous + '\n' + canonical(event)).encode('utf-8')).hexdigest()

class ReviewEventJournal:
    def __init__(self, path):
        self.db = sqlite3.connect(str(path), timeout=10, isolation_level=None)
        self.db.execute('PRAGMA busy_timeout=10000')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS review_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            migration_id TEXT NOT NULL,
            event_json TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL UNIQUE)''')
    def close(self): self.db.close()
    def __enter__(self): return self
    def __exit__(self, *args): self.close()
    def append(self, migration_id, action, actor, evidence_hash, *, now=None):
        if not all(isinstance(v, str) and v.strip() and len(v) <= 128 for v in (migration_id, actor)):
            raise JournalError('INVALID_IDENTITY')
        if action not in ('REVIEW_RECORDED', 'REVIEW_REVOKED', 'REVIEW_REJECTED'):
            raise JournalError('INVALID_ACTION')
        if not isinstance(evidence_hash, str) or len(evidence_hash) != 64 or any(c not in '0123456789abcdef' for c in evidence_hash):
            raise JournalError('INVALID_EVIDENCE_HASH')
        stamp = int(time.time()) if now is None else now
        if type(stamp) is not int or stamp < 0: raise JournalError('INVALID_TIME')
        event = dict(migration_id=migration_id, action=action, actor=actor, evidence_hash=evidence_hash, timestamp=stamp)
        try:
            self.db.execute('BEGIN IMMEDIATE')
            previous = self.db.execute('SELECT entry_hash FROM review_events ORDER BY seq DESC LIMIT 1').fetchone()
            prev_hash = previous[0] if previous else '0'*64
            digest = event_hash(prev_hash, event)
            self.db.execute('INSERT INTO review_events(migration_id,event_json,prev_hash,entry_hash) VALUES(?,?,?,?)',
                            (migration_id, canonical(event), prev_hash, digest))
            self.db.execute('COMMIT')
        except Exception:
            self.db.execute('ROLLBACK')
            raise
        return {'event_hash': digest, 'cutover_authorized': False}
    def verify(self):
        previous = '0'*64
        rows = self.db.execute('SELECT seq,event_json,prev_hash,entry_hash FROM review_events ORDER BY seq').fetchall()
        for expected_seq, (seq, raw, prev, stored) in enumerate(rows, 1):
            try:
                event = json.loads(raw)
                if canonical(event) != raw: raise ValueError('noncanonical')
                calculated = event_hash(previous, event)
            except (ValueError, TypeError):
                return {'status':'TAMPER_DETECTED','at_seq':seq,'cutover_authorized':False}
            if seq != expected_seq or prev != previous or stored != calculated:
                return {'status':'TAMPER_DETECTED','at_seq':seq,'cutover_authorized':False}
            previous = stored
        return {'status':'CHAIN_INTACT_UNAUTHENTICATED','events':len(rows),'head_hash':previous,'cutover_authorized':False}
