"""External-secret transactional collector registry, V209.2. Author: Abdelhalim Talbi.
No HMAC secret bytes are stored in SQLite. Existing V209.0 databases require a separate migration.
"""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from odmm_collector_registry_v2090 import CollectorRegistry
from odmm_netapp_collector_v2089 import verify_envelope, CollectorError
from odmm_trust_v2091 import ExternalSecretResolver

class ExternalKeyRegistry(CollectorRegistry):
    def __init__(self, path, resolver):
        if not isinstance(resolver, ExternalSecretResolver):
            raise TypeError('EXTERNAL_SECRET_RESOLVER_REQUIRED')
        self.resolver = resolver
        self.path = str(path)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            with sqlite3.connect(self.path) as db:
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if 'keys' in tables:
                    raise CollectorError('LEGACY_SECRET_DATABASE_REQUIRES_OFFLINE_MIGRATION')
        with self._connect() as db:
            db.executescript("""CREATE TABLE IF NOT EXISTS key_refs(
                collector TEXT NOT NULL,kid TEXT NOT NULL,status TEXT NOT NULL
                CHECK(status IN ('active','revoked')),PRIMARY KEY(collector,kid));
                CREATE TABLE IF NOT EXISTS nonces(collector TEXT NOT NULL,kid TEXT NOT NULL,
                nonce TEXT NOT NULL,seen_at TEXT NOT NULL,PRIMARY KEY(collector,kid,nonce));
                CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,details TEXT NOT NULL,previous_hash TEXT NOT NULL,entry_hash TEXT NOT NULL);
            """)
    def register_key_ref(self, collector, kid):
        # Resolve first, ensuring backend availability and minimum key strength.
        self.resolver.resolve(collector, kid)
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute("INSERT INTO key_refs VALUES(?,?,'active')", (collector,kid))
            except sqlite3.IntegrityError as exc:
                raise CollectorError('KEY_ID_ALREADY_USED') from exc
            self._audit(db,'KEY_REF_REGISTERED',{'collector':collector,'kid':kid})
            db.commit()
    def revoke_key(self, collector, kid):
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            cur=db.execute("UPDATE key_refs SET status='revoked' WHERE collector=? AND kid=? AND status='active'",(collector,kid))
            if cur.rowcount != 1: raise CollectorError('KEY_NOT_ACTIVE')
            self._audit(db,'KEY_REF_REVOKED',{'collector':collector,'kid':kid})
            db.commit()
    def verify_once(self, envelope, *, now=None, max_age_seconds=300):
        if not isinstance(envelope,dict): raise CollectorError('ENVELOPE_SCHEMA')
        collector,kid=envelope.get('collector_id'),envelope.get('key_id')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            active=db.execute("SELECT 1 FROM key_refs WHERE collector=? AND kid=? AND status='active'",(collector,kid)).fetchone()
            if not active: raise CollectorError('UNKNOWN_OR_REVOKED_KEY')
            secret=self.resolver.resolve(collector,kid)
            payload=verify_envelope(envelope,keyring={(collector,kid):secret},used_nonces=set(),now=now,max_age_seconds=max_age_seconds)
            try:
                db.execute('INSERT INTO nonces VALUES(?,?,?,?)',(collector,kid,envelope['nonce'],(now or datetime.now(timezone.utc)).isoformat()))
            except sqlite3.IntegrityError as exc:
                raise CollectorError('REPLAY_DETECTED') from exc
            self._audit(db,'ENVELOPE_ACCEPTED',{'collector':collector,'kid':kid,'nonce':envelope['nonce']})
            db.commit()
            return payload
    def register_key(self,*args,**kwargs):
        raise CollectorError('SECRET_STORAGE_FORBIDDEN_USE_KEY_REFERENCE')
