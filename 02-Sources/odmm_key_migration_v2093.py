"""Non-destructive legacy registry migration preflight. Author: Abdelhalim Talbi."""
import sqlite3
from pathlib import Path

def inspect_legacy_registry(path):
    """No secret reads; refuses ambiguous or inconsistent legacy schema."""
    p=Path(path)
    if not p.is_file(): return {'status':'BLOCKED','reason':'DATABASE_MISSING','cutover_authorized':False}
    try:
        with sqlite3.connect('file:'+str(p.resolve())+'?mode=ro',uri=True) as db:
            tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'keys' not in tables: return {'status':'BLOCKED','reason':'LEGACY_KEYS_MISSING','cutover_authorized':False}
            columns={r[1] for r in db.execute('PRAGMA table_info(keys)')}
            if not {'collector','kid','secret','status'}<=columns: return {'status':'BLOCKED','reason':'LEGACY_SCHEMA_INVALID','cutover_authorized':False}
            counts=dict(db.execute('SELECT status,COUNT(*) FROM keys GROUP BY status').fetchall())
            if set(counts)-{'active','revoked'}: return {'status':'BLOCKED','reason':'LEGACY_STATUS_INVALID','cutover_authorized':False}
            return {'status':'BLOCKED','reason':'OFFLINE_MIGRATION_AND_VAULT_REKEY_REQUIRED','cutover_authorized':False,'active_refs':counts.get('active',0),'revoked_refs':counts.get('revoked',0)}
    except (sqlite3.Error,ValueError,OSError):
        return {'status':'BLOCKED','reason':'LEGACY_DATABASE_UNREADABLE','cutover_authorized':False}
