"""Authenticated OIDC role administration facade; legacy raw gate is NOT disabled.

Bootstrap SECURITY grants must be provisioned out of band. Each administrative
operation consumes a fresh signed JWT and is serialized with the grant update.
"""
import hashlib
import json
from ldaps_oidc_rbac import OIDCRBACGate
from ldaps_transition_reconciliation import TransitionReconciliationError

class AuthenticatedRoleAdministration:
    def __init__(self, gate):
        if not isinstance(gate, OIDCRBACGate):
            raise TransitionReconciliationError('INVALID_ADMIN_GATE')
        self.gate=gate
        self.db=gate.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS oidc_admin_events (
          seq INTEGER PRIMARY KEY, actor TEXT NOT NULL, target TEXT NOT NULL,
          role TEXT NOT NULL, enabled INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE,
          event_time INTEGER NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL)''')

    @staticmethod
    def _digest(row):
        return hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def verify(self):
        rows=self.db.execute('SELECT seq,actor,target,role,enabled,token_hash,event_time,previous_hash,event_hash FROM oidc_admin_events ORDER BY seq').fetchall()
        prev='0'*64
        for expected,(seq,actor,target,role,enabled,token_hash,at,old,digest) in enumerate(rows,1):
            data=dict(seq=seq,actor=actor,target=target,role=role,enabled=enabled,token_hash=token_hash,event_time=at,previous_hash=prev)
            if seq!=expected or old!=prev or digest!=self._digest(data):
                raise TransitionReconciliationError('OIDC_ADMIN_AUDIT_TAMPERED')
            prev=digest
        return rows

    def set_grant(self, *, admin_token, target_subject, role, enabled, now):
        if not isinstance(target_subject,str) or not target_subject.strip() or len(target_subject)>128 or role not in ('SECURITY','OPERATIONS','AUDITOR') or type(enabled) is not bool or type(now) is not int or now<0:
            raise TransitionReconciliationError('INVALID_ADMIN_REQUEST')
        identity=self.gate.verifier.verify(admin_token,now=now)
        token_hash=hashlib.sha256(admin_token.encode('ascii')).hexdigest()
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.gate.registry.assert_active(issuer=identity['issuer'],subject=identity['subject'],token_id=identity['token_id'])
            rows=self.verify()
            if any(r[5]==token_hash for r in rows):
                raise TransitionReconciliationError('OIDC_ADMIN_TOKEN_REPLAY')
            admin=self.db.execute('SELECT enabled FROM oidc_rbac_grants WHERE issuer=? AND subject=? AND role=?',
                                  (identity['issuer'],identity['subject'],'SECURITY')).fetchone()
            if admin!=(1,):
                raise TransitionReconciliationError('OIDC_ADMIN_SECURITY_REQUIRED')
            if not enabled and role=='SECURITY' and target_subject==identity['subject']:
                raise TransitionReconciliationError('OIDC_ADMIN_SELF_REVOKE_DENIED')
            self.db.execute('INSERT INTO oidc_rbac_grants VALUES (?,?,?,?) ON CONFLICT(issuer,subject,role) DO UPDATE SET enabled=excluded.enabled',
                            (identity['issuer'],target_subject,role,int(enabled)))
            seq=len(rows)+1;prev=rows[-1][8] if rows else '0'*64
            item=dict(seq=seq,actor=identity['subject'],target=target_subject,role=role,enabled=int(enabled),token_hash=token_hash,event_time=now,previous_hash=prev)
            digest=self._digest(item)
            self.db.execute('INSERT INTO oidc_admin_events VALUES (?,?,?,?,?,?,?,?,?)',
                            (seq,identity['subject'],target_subject,role,int(enabled),token_hash,now,prev,digest))
            self.db.commit()
        except BaseException:
            self.db.rollback();raise
        return {'status':'ROLE_GRANT_UPDATED','audit_hash':digest,'execution_authorized':False,'cutover_authorized':False}
