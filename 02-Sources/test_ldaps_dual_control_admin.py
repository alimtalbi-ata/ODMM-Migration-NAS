import unittest
from test_ldaps_oidc_rbac import OIDCRBACTests
from ldaps_oidc_admin import AuthenticatedRoleAdministration
from ldaps_dual_control_admin import DualControlRoleAdministration
from ldaps_transition_reconciliation import TransitionReconciliationError

class DualControlTests(OIDCRBACTests):
    def setUp(self):
        super().setUp()
        self.admin=DualControlRoleAdministration(AuthenticatedRoleAdministration(self.gate))
        self.gate.provision(issuer=self.gate.verifier.issuer,subject='operator',role='OPERATIONS',enabled=True)
    def tok(self,subject,jti):
        return self.token({**self.claims,'sub':subject,'jti':jti})
    def change(self,sec=None,ops=None,**kw):
        return self.admin.set_grant(security_token=sec or self.tok('reviewer','sec1'),operations_token=ops or self.tok('operator','ops1'),target_subject=kw.get('target','new'),role=kw.get('role','AUDITOR'),enabled=kw.get('enabled',True),now=150)
    def test_success(self):
        self.assertFalse(self.change()['cutover_authorized'])
        self.assertEqual(self.db.execute("SELECT enabled FROM oidc_rbac_grants WHERE subject='new'").fetchone(),(1,))
    def test_replay(self):
        self.change()
        with self.assertRaisesRegex(TransitionReconciliationError,'REPLAY'):self.change(target='other')
    def test_independence(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'INDEPENDENT'):self.change(ops=self.tok('reviewer','ops2'))
    def test_missing_operations(self):
        self.gate.provision(issuer=self.gate.verifier.issuer,subject='operator',role='OPERATIONS',enabled=False)
        with self.assertRaisesRegex(TransitionReconciliationError,'ROLE_REQUIRED'):self.change()
    def test_missing_security(self):
        self.gate.provision(issuer=self.gate.verifier.issuer,subject='reviewer',role='SECURITY',enabled=False)
        with self.assertRaisesRegex(TransitionReconciliationError,'ROLE_REQUIRED'):self.change()
    def test_revoked(self):
        self.registry.revoke(kind='token',identifier='ops1',now=100)
        with self.assertRaises(TransitionReconciliationError):self.change()
    def test_bad_signature(self):
        with self.assertRaises(TransitionReconciliationError):self.change(sec=self.tok('reviewer','sec1')+'x')
    def test_tamper(self):
        self.change()
        self.db.execute("UPDATE oidc_dual_control_events SET target='tampered'")
        with self.assertRaisesRegex(TransitionReconciliationError,'TAMPERED'):self.admin.verify()
    def test_tamper_blocks(self):
        self.change()
        self.db.execute("UPDATE oidc_dual_control_events SET enabled=0")
        with self.assertRaises(TransitionReconciliationError):self.change(sec=self.tok('reviewer','sec2'),ops=self.tok('operator','ops2'))
    def test_rollback(self):
        with self.assertRaises(TransitionReconciliationError):self.change(role='ROOT')
        self.assertEqual(len(self.admin.verify()),0)
    def test_self_revoke(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'SELF_REVOKE'):self.change(target='reviewer',role='SECURITY',enabled=False)
    def test_reopen(self):
        self.change()
        self.assertEqual(len(DualControlRoleAdministration(AuthenticatedRoleAdministration(self.gate)).verify()),1)
