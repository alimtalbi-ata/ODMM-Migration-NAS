import unittest
from test_ldaps_freshness_policy_audit import Tests as BaseTests
from ldaps_strict_security import StrictSecurityMode
from ldaps_rbac_reconciliation import ReconciliationRBACError

class StrictModeTests(BaseTests):
    def test_legacy_default(self):
        self.assertFalse(StrictSecurityMode(self.rbac).enabled())
    def test_enable_requires_policy(self):
        self.apply()
        with self.assertRaisesRegex(ReconciliationRBACError,'NOT_INITIALIZED'):
            StrictSecurityMode(self.rbac).enable(now=102)
    def test_enable_valid(self):
        self.setup_policy()
        self.assertEqual(StrictSecurityMode(self.rbac).enable(now=105)['status'],'STRICT_SECURITY_ENABLED')
    def test_restart_persistence(self):
        self.setup_policy();StrictSecurityMode(self.rbac).enable(now=105)
        self.assertTrue(StrictSecurityMode(self.rbac).enabled())
    def test_duplicate_enable(self):
        self.setup_policy();mode=StrictSecurityMode(self.rbac);mode.enable(now=105)
        with self.assertRaisesRegex(ReconciliationRBACError,'ALREADY_ENABLED'):mode.enable(now=105)
    def test_stale_blocks(self):
        self.setup_policy();mode=StrictSecurityMode(self.rbac);mode.enable(now=105)
        with self.assertRaisesRegex(ReconciliationRBACError,'NOT_FRESH'):mode.guard(now=112)
    def test_future_blocks(self):
        self.setup_policy();mode=StrictSecurityMode(self.rbac);mode.enable(now=105)
        with self.assertRaisesRegex(ReconciliationRBACError,'NOT_FRESH'):mode.guard(now=100)
    def test_tamper_blocks(self):
        self.setup_policy();mode=StrictSecurityMode(self.rbac);mode.enable(now=105)
        self.a.execute('UPDATE ldaps_freshness_policy_audit SET new_limit=999')
        with self.assertRaisesRegex(ReconciliationRBACError,'TAMPERED'):mode.guard(now=105)
    def test_no_cutover(self):
        self.setup_policy();self.assertFalse(StrictSecurityMode(self.rbac).enable(now=105)['cutover_authorized'])
    def test_invalid_timestamp(self):
        with self.assertRaisesRegex(ReconciliationRBACError,'INVALID_TIMESTAMP'):StrictSecurityMode(self.rbac).enable(now=True)
