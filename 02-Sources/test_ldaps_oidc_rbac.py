import unittest
from test_ldaps_oidc_identity import OIDCTests
from ldaps_oidc_rbac import OIDCRBACGate
from ldaps_transition_reconciliation import TransitionReconciliationError

class OIDCRBACTests(OIDCTests):
    def setUp(self):
        super().setUp()
        self.gate=OIDCRBACGate(self.v,self.registry,self.db)
        self.gate.provision(issuer=self.v.issuer,subject='reviewer',role='SECURITY',enabled=True)
    def authorize(self,token=None,role='SECURITY'):
        return self.gate.authorize(token=token or self.token(),required_role=role,now=150)
    def test_authorized(self):
        result=self.authorize();self.assertTrue(result['role_authorized']);self.assertFalse(result['cutover_authorized'])
    def test_denied_ungranted(self):
        with self.assertRaises(TransitionReconciliationError):self.authorize(role='OPERATIONS')
    def test_disabled(self):
        self.gate.provision(issuer=self.v.issuer,subject='reviewer',role='SECURITY',enabled=False)
        with self.assertRaises(TransitionReconciliationError):self.authorize()
    def test_replay(self):
        self.authorize()
        with self.assertRaisesRegex(TransitionReconciliationError,'REPLAY'):self.authorize()
    def test_other_token_same_subject(self):
        self.authorize();self.assertTrue(self.authorize(self.token({**self.claims,'jti':'jwt-2'}))['role_authorized'])
    def test_revoked_subject(self):
        self.registry.revoke(kind='subject',identifier='reviewer',now=100)
        with self.assertRaises(TransitionReconciliationError):self.authorize()
    def test_revoked_token(self):
        self.registry.revoke(kind='token',identifier='jwt-1',now=100)
        with self.assertRaises(TransitionReconciliationError):self.authorize()
    def test_bad_signature(self):
        with self.assertRaises(TransitionReconciliationError):self.authorize(self.token()+'x')
    def test_audit_tamper(self):
        self.authorize();self.db.execute("UPDATE oidc_rbac_decisions SET subject='attacker'")
        with self.assertRaisesRegex(TransitionReconciliationError,'TAMPERED'):self.gate.verify_audit()
    def test_audit_tamper_blocks_next(self):
        self.authorize();self.db.execute("UPDATE oidc_rbac_decisions SET role='AUDITOR'")
        with self.assertRaises(TransitionReconciliationError):self.authorize(self.token({**self.claims,'jti':'jwt-2'}))
    def test_wrong_issuer_provision(self):
        with self.assertRaises(TransitionReconciliationError):self.gate.provision(issuer='https://other',subject='reviewer',role='SECURITY',enabled=True)
    def test_no_implicit_grant(self):
        self.assertFalse(self.v.verify(self.token(),now=150)['roles_authorized'])
    def test_invalid_role(self):
        with self.assertRaises(TransitionReconciliationError):self.authorize(role='ADMIN')
