"""Persistent issuer/subject/token revocation for HMAC recovery assertions.

Local security control only; not an OIDC/LDAP authentication implementation.
"""
import hashlib
import hmac
import json

from ldaps_transition_reconciliation import TransitionReconciliationError


class IdentityRevocationRegistry:
    def __init__(self, db):
        self.db = db
        self.db.execute("""CREATE TABLE IF NOT EXISTS identity_revocations (
            seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, identifier TEXT NOT NULL,
            revoked_at INTEGER NOT NULL, previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL, UNIQUE(kind, identifier))""")

    @staticmethod
    def _digest(seq, kind, identifier, at, prev):
        payload = [seq, kind, identifier, at, prev]
        return hashlib.sha256(json.dumps(payload, separators=(',', ':')).encode()).hexdigest()

    def verify(self):
        rows = self.db.execute('SELECT seq,kind,identifier,revoked_at,previous_hash,event_hash FROM identity_revocations ORDER BY seq').fetchall()
        prev = '0' * 64
        for expected, (seq, kind, identifier, at, previous, digest) in enumerate(rows, 1):
            if (seq != expected or kind not in ('issuer','subject','token') or
                not isinstance(identifier,str) or not identifier or type(at) is not int or at < 0 or
                previous != prev or not hmac.compare_digest(digest, self._digest(seq,kind,identifier,at,prev))):
                raise TransitionReconciliationError('IDENTITY_REVOCATION_AUDIT_TAMPERED')
            prev = digest
        return rows

    def revoke(self, *, kind, identifier, now):
        if kind not in ('issuer','subject','token') or not isinstance(identifier,str) or not identifier.strip() or len(identifier)>128 or type(now) is not int or now < 0:
            raise TransitionReconciliationError('INVALID_REVOCATION')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            rows = self.verify()
            if any(r[1] == kind and r[2] == identifier for r in rows):
                raise TransitionReconciliationError('REVOCATION_ALREADY_RECORDED')
            if rows and now < rows[-1][3]:
                raise TransitionReconciliationError('REVOCATION_TIME_REGRESSION')
            seq = len(rows) + 1
            prev = rows[-1][5] if rows else '0'*64
            digest = self._digest(seq,kind,identifier,now,prev)
            self.db.execute('INSERT INTO identity_revocations VALUES (?,?,?,?,?,?)', (seq,kind,identifier,now,prev,digest))
            self.db.commit()
            return {'revoked':True,'event_hash':digest,'cutover_authorized':False}
        except BaseException:
            self.db.rollback()
            raise

    def assert_active(self, *, issuer, subject, token_id):
        rows = self.verify()
        blocked = {('issuer',issuer),('subject',subject),('token',token_id)}
        if any((row[1],row[2]) in blocked for row in rows):
            raise TransitionReconciliationError('IDENTITY_REVOKED')
        return True


class RevocationGuardedAckRecovery:
    """Fail-closed wrapper for authenticated recovery; no direct LDAP access."""
    def __init__(self, authenticated_recovery, registry):
        from ldaps_authenticated_ack_recovery import AuthenticatedAckRecovery
        if not isinstance(authenticated_recovery, AuthenticatedAckRecovery) or not isinstance(registry, IdentityRevocationRegistry) or authenticated_recovery.db is not registry.db:
            raise TransitionReconciliationError('INVALID_REVOCATION_GUARD')
        self.authenticated_recovery = authenticated_recovery
        self.registry = registry

    def recover(self, *, token, original_operator, operator_confirmed, now, max_age_seconds):
        if not isinstance(token, dict):
            raise TransitionReconciliationError('INVALID_IDENTITY_TOKEN')
        # Authentication precedes revocation checking to avoid accepting forged claims.
        self.authenticated_recovery._authenticate(token, now)
        self.registry.assert_active(issuer=token['issuer'],subject=token['subject'],token_id=token['token_id'])
        return self.authenticated_recovery.recover(token=token,original_operator=original_operator,
            operator_confirmed=operator_confirmed,now=now,max_age_seconds=max_age_seconds)
