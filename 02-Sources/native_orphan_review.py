"""Fail-closed, durable orphan review; never deletes or renames target data."""
import hashlib
import json
import os
import sqlite3
import stat
import time
from native_orphan_inventory import inspect_orphans
from native_dirfd_guard import parent_fd
from native_migration_errors import MigrationBlocked
from native_orphan_audit import append as append_audit


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _file_identity(engine, path):
    with parent_fd(engine.target, path, root_fd=engine._root_fds[1]) as (directory, name):
        st = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            raise MigrationBlocked('UNSAFE_ORPHAN_ENTRY')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            if _identity(os.fstat(fd)) != _identity(st):
                raise MigrationBlocked('ORPHAN_REPLACED')
            return _identity(st)
        finally:
            os.close(fd)


def _init(engine):
    engine.db.execute('''CREATE TABLE IF NOT EXISTS orphan_reviews (
        review_id TEXT PRIMARY KEY, path TEXT NOT NULL, identity_json TEXT NOT NULL,
        created_ns INTEGER NOT NULL, state TEXT NOT NULL, operator TEXT,
        rationale TEXT, reviewed_ns INTEGER)''')


def create_review(engine, relative_directory=''):
    """Capture candidate identities and pending native intents; no cleanup authority."""
    rows = inspect_orphans(engine, relative_directory)
    with engine._exclusive():
        engine._check_roots()
        _init(engine)
        result = []
        for row in rows:
            ident = _file_identity(engine, row['path'])
            directory = row['path'].rsplit('/', 1)[0] if '/' in row['path'] else ''
            pending = engine.db.execute('SELECT path FROM intents WHERE path=? OR path LIKE ?', (directory, directory + '/%') if directory else ('', '%')).fetchall()
            payload = json.dumps({'path': row['path'], 'identity': ident}, sort_keys=True)
            rid = hashlib.sha256(payload.encode()).hexdigest()
            engine.db.execute('INSERT OR IGNORE INTO orphan_reviews(review_id,path,identity_json,created_ns,state) VALUES (?,?,?,?,?)', (rid,row['path'],json.dumps(ident),time.time_ns(),'PENDING'))
            result.append({'review_id':rid,'path':row['path'],'identity':ident,'pending_intents_in_directory':len(pending),'status':'REVIEW_REQUIRED','auto_delete_authorized':False,'cutover_authorized':False})
        return result


def approve_for_manual_investigation(engine, review_id, *, operator, rationale, audit_key=None, segment_keys=None):
    """Record approval for external investigation ONLY, not deletion."""
    if audit_key is None:
        raise MigrationBlocked('AUDIT_KEY_REQUIRED')
    if not operator or not operator.strip() or not rationale or len(rationale.strip()) < 10:
        raise MigrationBlocked('REVIEW_REASON_REQUIRED')
    with engine._exclusive():
        engine._check_roots()
        _init(engine)
        row = engine.db.execute('SELECT path,identity_json,state FROM orphan_reviews WHERE review_id=?', (review_id,)).fetchone()
        if not row or row[2] != 'PENDING':
            raise MigrationBlocked('REVIEW_NOT_PENDING')
        try:
            current = _file_identity(engine,row[0])
        except FileNotFoundError:
            raise MigrationBlocked('ORPHAN_MISSING')
        if tuple(json.loads(row[1])) != current:
            raise MigrationBlocked('ORPHAN_REPLACED')
        # The journal may contain a pending publication in the same directory.
        directory = row[0].rsplit('/', 1)[0] if '/' in row[0] else ''
        pending = engine.db.execute('SELECT path FROM intents').fetchall()
        if any((p[0].rsplit('/',1)[0] if '/' in p[0] else '') == directory for p in pending):
            raise MigrationBlocked('PENDING_INTENT_IN_DIRECTORY')
        engine.db.execute('BEGIN IMMEDIATE')
        try:
            cur = engine.db.execute('UPDATE orphan_reviews SET state=?,operator=?,rationale=?,reviewed_ns=? WHERE review_id=? AND state=?', ('MANUAL_INVESTIGATION_ONLY',operator,rationale,time.time_ns(),review_id,'PENDING'))
            if cur.rowcount != 1:
                raise MigrationBlocked('REVIEW_CONFLICT')
            evidence = append_audit(engine.db, audit_key, kind='MANUAL_INVESTIGATION_ONLY', review_id=review_id, path=row[0], operator=operator, rationale=rationale)
            from native_audit_bridge import append_decision
            bridge_active = engine.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_bridge_state'").fetchone()
            if bridge_active and engine.db.execute('SELECT 1 FROM audit_bridge_state WHERE id=1').fetchone():
                if not segment_keys:
                    raise MigrationBlocked('BRIDGE_KEYS_REQUIRED')
                append_decision(engine.db, legacy_key=audit_key, segment_keys=segment_keys,
                                event={'review_id':review_id,'path':row[0],'operator':operator,'rationale':rationale})
            engine.db.execute('COMMIT')
        except BaseException:
            engine.db.execute('ROLLBACK')
            raise
        return {'status':'MANUAL_INVESTIGATION_ONLY','path':row[0], 'auto_delete_authorized':False,'cutover_authorized':False, 'audit':evidence}
