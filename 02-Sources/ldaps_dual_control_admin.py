"""Opt-in two-person OIDC role administration, fail-closed; no migration effects.

This is a secure facade, NOT a global interception of legacy APIs. SECURITY and
OPERATIONS identities must be different, independently granted and unrevoked.
"""
import hashlib
import json
from ldaps_oidc_admin import AuthenticatedRoleAdministration
from ldaps_transition_reconciliation import TransitionReconciliationError

class DualControlRoleAdministration:
    def __init__(self, admin):
        if not isinstance(admin, AuthenticatedRoleAdministration):
            raise TransitionReconciliationError('INVALID_DUAL_CONTROL_ADMIN')
        self.admin=admin
        self.gate=admin.gate
        self.db=admin.db
        self.db.execute('''CREATE TABLE IF NOT EXISTS oidc_dual_control_events (
            seq INTEGER PRIMARY KEY, security_subject TEXT NOT NULL,
            operations_subject TEXT NOT NULL, target TEXT NOT NULL,
            role TEXT NOT NULL, enabled INTEGER NOT NULL,
            security_token_hash TEXT NOT NULL UNIQUE,
            operations_token_hash TEXT NOT NULL UNIQUE,
            event_time INTEGER NOT NULL, previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL)''')

    @staticmethod
    def _hash(obj):
        return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def verify(self):
        rows=self.db.execute('SELECT seq,security_subject,operations_subject,target,role,enabled,security_token_hash,operations_token_hash,event_time,previous_hash,event_hash FROM oidc_dual_control_events ORDER BY seq').fetchall()
        previous='0'*64
        for seq,(n,sec,ops,target,role,enabled,sh,oh,at,prev,digest) in enumerate(rows,1):
            obj=dict(seq=seq,security_subject=sec,operations_subject=ops,target=target,role=role,enabled=enabled,security_token_hash=sh,operations_token_hash=oh,event_time=at,previous_hash=previous)
            if n!=seq or prev!=previous or digest!=self._hash(obj):
                raise TransitionReconciliationError('DUAL_CONTROL_AUDIT_TAMPERED')
            previous=digest
        return rows

    def set_grant(self, *, security_token, operations_token, target_subject, role, enabled, now):
        if not isinstance(target_subject,str) or not target_subject.strip() or len(target_subject)>128 or role not in ('SECURITY','OPERATIONS','AUDITOR') or type(enabled)!=bool or type(now)!=int or now<0:
            raise TransitionReconciliationError('INVALID_DUAL_CONTROL_REQUEST')
        sec=self.gate.verifier.verify(security_token,now=now)
        ops=self.gate.verifier.verify(operations_token,now=now)
        if sec['subject']==ops['subject'] or sec['token_id']==ops['token_id']:
            raise TransitionReconciliationError('DUAL_CONTROL_INDEPENDENT_IDENTITIES_REQUIRED')
        sh=hashlib.sha256(security_token.encode('ascii')).hexdigest()
        oh=hashlib.sha256(operations_token.encode('ascii')).hexdigest()
        if sh==oh:
            raise TransitionReconciliationError('DUAL_CONTROL_DISTINCT_TOKENS_REQUIRED')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.gate.registry.assert_active(issuer=sec['issuer'],subject=sec['subject'],token_id=sec['token_id'])
            self.gate.registry.assert_active(issuer=ops['issuer'],subject=ops['subject'],token_id=ops['token_id'])
            self.admin.verify()
            self.gate.verify_audit()
            rows=self.verify()
            if any(sh in (r[6],r[7]) or oh in (r[6],r[7]) for r in rows):
                raise TransitionReconciliationError('DUAL_CONTROL_TOKEN_REPLAY')
            for identity,required in ((sec,'SECURITY'),(ops,'OPERATIONS')):
                grant=self.db.execute('SELECT enabled FROM oidc_rbac_grants WHERE issuer=? AND subject=? AND role=?',(identity['issuer'],identity['subject'],required)).fetchone()
                if grant!=(1,):
                    raise TransitionReconciliationError('DUAL_CONTROL_ROLE_REQUIRED')
            if not enabled and role=='SECURITY' and target_subject==sec['subject']:
                raise TransitionReconciliationError('DUAL_CONTROL_SELF_REVOKE_DENIED')
            self.db.execute('INSERT INTO oidc_rbac_grants VALUES (?,?,?,?) ON CONFLICT(issuer,subject,role) DO UPDATE SET enabled=excluded.enabled',(sec['issuer'],target_subject,role,int(enabled)))
            seq=len(rows)+1
            previous=rows[-1][10] if rows else '0'*64
            obj=dict(seq=seq,security_subject=sec['subject'],operations_subject=ops['subject'],target=target_subject,role=role,enabled=int(enabled),security_token_hash=sh,operations_token_hash=oh,event_time=now,previous_hash=previous)
            digest=self._hash(obj)
            self.db.execute('INSERT INTO oidc_dual_control_events VALUES (?,?,?,?,?,?,?,?,?,?,?)',(seq,sec['subject'],ops['subject'],target_subject,role,int(enabled),sh,oh,now,previous,digest))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        return {'status':'DUAL_CONTROL_GRANT_UPDATED','audit_hash':digest,'execution_authorized':False,'cutover_authorized':False}
