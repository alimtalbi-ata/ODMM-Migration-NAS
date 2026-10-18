"""Fail-closed OIDC identity to locally provisioned RBAC mapping.

This is an authorization decision, NOT a recovery execution endpoint.  The
existing legacy recovery APIs remain callable and require separate isolation.
"""
import hashlib
import hmac
import json
from ldaps_oidc_identity import OIDCIdentityVerifier
from ldaps_identity_revocation import IdentityRevocationRegistry
from ldaps_transition_reconciliation import TransitionReconciliationError


class OIDCRBACGate:
    def __init__(self, verifier, registry, db):
        if not isinstance(verifier, OIDCIdentityVerifier) or not isinstance(registry, IdentityRevocationRegistry) or registry.db is not db or verifier.registry is not registry:
            raise TransitionReconciliationError('OIDC_RBAC_GUARD_CONFIGURATION_INVALID')
        self.verifier, self.registry, self.db = verifier, registry, db
        db.execute('''CREATE TABLE IF NOT EXISTS oidc_rbac_grants (
          issuer TEXT NOT NULL, subject TEXT NOT NULL, role TEXT NOT NULL,
          enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
          PRIMARY KEY(issuer,subject,role))''')
        db.execute('''CREATE TABLE IF NOT EXISTS oidc_rbac_decisions (
          seq INTEGER PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL,
          token_hash TEXT NOT NULL, role TEXT NOT NULL, decision_time INTEGER NOT NULL,
          previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)''')

    def provision(self, *, issuer, subject, role, enabled):
        """Privileged provisioning only; caller MUST enforce admin authentication."""
        if issuer != self.verifier.issuer or not isinstance(subject,str) or not subject.strip() or len(subject)>128 or role not in ('SECURITY','OPERATIONS','AUDITOR') or type(enabled) is not bool:
            raise TransitionReconciliationError('INVALID_OIDC_RBAC_GRANT')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('INSERT INTO oidc_rbac_grants VALUES (?,?,?,?) ON CONFLICT(issuer,subject,role) DO UPDATE SET enabled=excluded.enabled',(issuer,subject,role,int(enabled)))
            self.db.commit()
        except BaseException:
            self.db.rollback();raise

    @staticmethod
    def _digest(row):
        return hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def verify_audit(self):
        rows=self.db.execute('SELECT seq,issuer,subject,token_hash,role,decision_time,previous_hash,event_hash FROM oidc_rbac_decisions ORDER BY seq').fetchall()
        prev='0'*64
        for n,(seq,issuer,subject,token_hash,role,at,old,digest) in enumerate(rows,1):
            obj=dict(seq=seq,issuer=issuer,subject=subject,token_hash=token_hash,role=role,decision_time=at,previous_hash=prev)
            if seq!=n or old!=prev or not hmac.compare_digest(digest,self._digest(obj)):
                raise TransitionReconciliationError('OIDC_RBAC_AUDIT_TAMPERED')
            prev=digest
        return rows

    def authorize(self, *, token, required_role, now):
        if required_role not in ('SECURITY','OPERATIONS','AUDITOR') or type(now) is not int or now<0:
            raise TransitionReconciliationError('INVALID_OIDC_RBAC_REQUEST')
        identity=self.verifier.verify(token,now=now)
        if identity['issuer']!=self.verifier.issuer:
            raise TransitionReconciliationError('OIDC_RBAC_ISSUER_MISMATCH')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.registry.assert_active(issuer=identity['issuer'],subject=identity['subject'],token_id=identity['token_id'])
            rows=self.verify_audit()
            grant=self.db.execute('SELECT enabled FROM oidc_rbac_grants WHERE issuer=? AND subject=? AND role=?',(identity['issuer'],identity['subject'],required_role)).fetchone()
            if grant!=(1,):
                raise TransitionReconciliationError('OIDC_RBAC_DENIED')
            token_hash=hashlib.sha256(token.encode('ascii')).hexdigest()
            if any(r[3]==token_hash and r[4]==required_role for r in rows):
                raise TransitionReconciliationError('OIDC_RBAC_TOKEN_REPLAY')
            seq=len(rows)+1;prev=rows[-1][7] if rows else '0'*64
            obj=dict(seq=seq,issuer=identity['issuer'],subject=identity['subject'],token_hash=token_hash,role=required_role,decision_time=now,previous_hash=prev)
            digest=self._digest(obj)
            self.db.execute('INSERT INTO oidc_rbac_decisions VALUES (?,?,?,?,?,?,?,?)',(seq,identity['issuer'],identity['subject'],token_hash,required_role,now,prev,digest))
            self.db.commit()
        except BaseException:
            self.db.rollback();raise
        return {'identity_verified':True,'role_authorized':True,'issuer':identity['issuer'],'subject':identity['subject'],'role':required_role,'decision_hash':digest,'recovery_authorized':False,'execution_authorized':False,'cutover_authorized':False}
