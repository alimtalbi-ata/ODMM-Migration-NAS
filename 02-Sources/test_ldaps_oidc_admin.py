import unittest
from test_ldaps_oidc_rbac import OIDCRBACTests
from ldaps_oidc_admin import AuthenticatedRoleAdministration
from ldaps_transition_reconciliation import TransitionReconciliationError

class OIDCAdminTests(OIDCRBACTests):
    def setUp(self):
        super().setUp()
        self.admin=AuthenticatedRoleAdministration(self.gate)
    def admin_token(self, jti='admin-1', sub='reviewer'):
        return self.token({**self.claims,'sub':sub,'jti':jti})
    def test_grant(self):
        result=self.admin.set_grant(admin_token=self.admin_token(),target_subject='new',role='OPERATIONS',enabled=True,now=150)
        self.assertFalse(result['cutover_authorized'])
        self.assertEqual(self.db.execute("SELECT enabled FROM oidc_rbac_grants WHERE subject='new'").fetchone(),(1,))
    def test_revoke(self):
        self.admin.set_grant(admin_token=self.admin_token(),target_subject='new',role='SECURITY',enabled=False,now=150)
        self.assertEqual(self.db.execute("SELECT enabled FROM oidc_rbac_grants WHERE subject='new'").fetchone(),(0,))
    def test_replay(self):
        self.admin.set_grant(admin_token=self.admin_token(),target_subject='new',role='AUDITOR',enabled=True,now=150)
        with self.assertRaisesRegex(TransitionReconciliationError,'REPLAY'):
            self.admin.set_grant(admin_token=self.admin_token(),target_subject='other',role='AUDITOR',enabled=True,now=150)
    def test_unauthorized(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'SECURITY_REQUIRED'):
            self.admin.set_grant(admin_token=self.admin_token(sub='stranger'),target_subject='new',role='AUDITOR',enabled=True,now=150)
    def test_self_revoke(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'SELF_REVOKE'):
            self.admin.set_grant(admin_token=self.admin_token(),target_subject='reviewer',role='SECURITY',enabled=False,now=150)
    def test_revoked_token(self):
        self.registry.revoke(kind='token',identifier='admin-1',now=100)
        with self.assertRaises(TransitionReconciliationError):
            self.admin.set_grant(admin_token=self.admin_token(),target_subject='new',role='AUDITOR',enabled=True,now=150)
    def test_invalid_signature(self):
        with self.assertRaises(TransitionReconciliationError):
            self.admin.set_grant(admin_token=self.admin_token()+'x',target_subject='new',role='AUDITOR',enabled=True,now=150)
    def test_audit_tamper(self):
        self.admin.set_grant(admin_token=self.admin_token(),target_subject='new',role='AUDITOR',enabled=True,now=150)
        self.db.execute("UPDATE oidc_admin_events SET target='bad'")
        with self.assertRaisesRegex(TransitionReconciliationError,'TAMPERED'):self.admin.verify()
    def test_audit_tamper_blocks_next(self):
        self.admin.set_grant(admin_token=self.admin_token(),target_subject='new',role='AUDITOR',enabled=True,now=150)
        self.db.execute("UPDATE oidc_admin_events SET enabled=0")
        with self.assertRaises(TransitionReconciliationError):
            self.admin.set_grant(admin_token=self.admin_token('admin-2'),target_subject='new',role='OPERATIONS',enabled=True,now=150)
    def test_bad_role(self):
        with self.assertRaises(TransitionReconciliationError):
            self.admin.set_grant(admin_token=self.admin_token(),target_subject='new',role='ADMIN',enabled=True,now=150)
    def test_bad_target(self):
        with self.assertRaises(TransitionReconciliationError):
            self.admin.set_grant(admin_token=self.admin_token(),target_subject='',role='AUDITOR',enabled=True,now=150)
    def test_persistent_reopen(self):
        self.admin.set_grant(admin_token=self.admin_token(),target_subject='new',role='AUDITOR',enabled=True,now=150)
        self.assertEqual(len(AuthenticatedRoleAdministration(self.gate).verify()),1)
