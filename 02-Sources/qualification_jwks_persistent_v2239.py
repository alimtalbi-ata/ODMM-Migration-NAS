"""SQLite-backed JWKS CAS coordination. Author: Abdelhalim Talbi.

All writers MUST use this coordinator; SQLite is not a distributed HA quorum.
Database rollback needs an independent trusted generation/digest witness.
"""
import json
import sqlite3
from pathlib import Path
from qualification_jwks_rotation_v2238 import PinnedJWKSRotation, jwks_digest

class PersistentJWKSRotation:
    def __init__(self, *, path, issuer, audience, initial_jwks, role_claim='roles', allowed_roles=None, clock=None):
        self.path = str(path)
        self.settings = dict(issuer=issuer, audience=audience, role_claim=role_claim,
                             allowed_roles=allowed_roles, clock=clock)
        PinnedJWKSRotation(jwks=initial_jwks, **self.settings)
        self.initial_digest = jwks_digest(initial_jwks)
        with self._connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS jwks_state (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL, genesis TEXT NOT NULL)')
            db.execute('INSERT OR IGNORE INTO jwks_state VALUES (1,0,?,?,?)',
                       (self.initial_digest, json.dumps(initial_jwks, sort_keys=True), self.initial_digest))
            self._load(db)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.execute('PRAGMA busy_timeout=5000')
        return db

    def _load(self, db):
        row = db.execute('SELECT generation,digest,payload,genesis FROM jwks_state WHERE id=1').fetchone()
        if not row or row[3] != self.initial_digest or row[0] < 0:
            raise ValueError('JWKS_PERSISTENCE_INTEGRITY')
        try:
            jwks = json.loads(row[2])
            if jwks_digest(jwks) != row[1]: raise ValueError('JWKS_PERSISTENCE_INTEGRITY')
            manager = PinnedJWKSRotation(jwks=jwks, **self.settings)
        except (TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ValueError('JWKS_PERSISTENCE_INTEGRITY') from exc
        return row[0], row[1], jwks, manager

    @property
    def state(self):
        with self._connect() as db:
            generation, digest, jwks, manager = self._load(db)
            return dict(generation=generation, jwks_sha256=digest, key_count=manager.state['key_count'])

    def verify(self, token):
        with self._connect() as db:
            return self._load(db)[3].verify(token)

    def resolve_request(self, request):
        with self._connect() as db:
            return self._load(db)[3].resolve_request(request)

    def rotate(self, *, jwks, expected_generation, expected_sha256, expected_previous_sha256,
               require_overlap=True):
        db = self._connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            generation, digest, old, manager = self._load(db)
            if expected_generation != generation or expected_previous_sha256 != digest:
                raise ValueError('JWKS_ROTATION_STALE')
            manager.rotate(jwks=jwks, expected_generation=0,
                           expected_sha256=expected_sha256,
                           expected_previous_sha256=digest, require_overlap=require_overlap)
            new_generation = generation + 1
            db.execute('UPDATE jwks_state SET generation=?, digest=?, payload=? WHERE id=1',
                       (new_generation, expected_sha256, json.dumps(jwks, sort_keys=True)))
            db.execute('COMMIT')
            return self.state
        except BaseException:
            db.execute('ROLLBACK')
            raise
        finally:
            db.close()
