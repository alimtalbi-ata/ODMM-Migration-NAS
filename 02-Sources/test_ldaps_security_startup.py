import unittest
from test_ldaps_freshness_policy_audit import Tests as BaseTests
from ldaps_security_startup import verify_startup
from ldaps_rbac_reconciliation import ReconciliationRBACError

class StartupTests(BaseTests):
 def test_valid(self):
  self.setup_policy();self.assertTrue(verify_startup(self.rbac,now=105)['review_allowed'])
 def test_stale(self):
  self.setup_policy()
  with self.assertRaisesRegex(ReconciliationRBACError,'NOT_FRESH'):verify_startup(self.rbac,now=112)
 def test_future(self):
  self.setup_policy()
  with self.assertRaisesRegex(ReconciliationRBACError,'NOT_FRESH'):verify_startup(self.rbac,now=100)
 def test_no_policy(self):
  self.apply()
  with self.assertRaisesRegex(ReconciliationRBACError,'NOT_INITIALIZED'):verify_startup(self.rbac,now=102)
 def test_tamper(self):
  self.setup_policy();self.a.execute('UPDATE ldaps_freshness_policy_audit SET new_limit=900')
  with self.assertRaisesRegex(ReconciliationRBACError,'TAMPERED'):verify_startup(self.rbac,now=105)
 def test_no_cutover(self):
  self.setup_policy();self.assertFalse(verify_startup(self.rbac,now=105)['cutover_authorized'])
 def test_invalid_clock(self):
  with self.assertRaisesRegex(ReconciliationRBACError,'INVALID_TIMESTAMP'):verify_startup(self.rbac,now=True)
 def test_restart(self):
  self.setup_policy();self.assertEqual(verify_startup(self.rbac,now=105)['status'],'STARTUP_SECURITY_CHECK_PASSED')
