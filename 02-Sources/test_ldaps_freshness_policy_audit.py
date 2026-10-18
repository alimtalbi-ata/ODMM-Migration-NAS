import unittest,sqlite3
from test_ldaps_directory_rbac_bridge import Tests as BaseTests
from ldaps_freshness_policy_audit import AuditedFreshnessPolicy
from ldaps_rbac_reconciliation import ReconciliationRBACError

class Tests(BaseTests):
 def setUp(self):
  super().setUp();self.policy=AuditedFreshnessPolicy(self.rbac)
 def setup_policy(self,**kw):
  self.apply()
  return self.policy.configure(max_age_seconds=10,security_reviewer='sec',operations_reviewer='ops',now=102,**kw)
 def test_initial_policy(self):
  self.assertEqual(self.setup_policy()['status'],'AUDITED_FRESHNESS_POLICY_ENABLED')
 def test_verify(self):
  self.setup_policy();self.assertEqual(self.policy.verify()['events'],1)
 def test_no_execution(self):
  x=self.setup_policy();self.assertFalse(x['execution_authorized']);self.assertFalse(x['cutover_authorized'])
 def test_reconfigure(self):
  self.setup_policy();self.policy.configure(max_age_seconds=20,security_reviewer='sec',operations_reviewer='ops',now=103)
  self.assertEqual(self.policy.verify()['events'],2)
 def test_no_refresh_on_reconfigure(self):
  self.setup_policy();self.policy.configure(max_age_seconds=20,security_reviewer='sec',operations_reviewer='ops',now=103)
  self.assertEqual(self.a.execute('SELECT synced_at FROM ldaps_rbac_directory_freshness').fetchone()[0],101)
 def test_no_snapshot(self):
  with self.assertRaisesRegex(ReconciliationRBACError,'SNAPSHOT_REQUIRED'):
   self.policy.configure(max_age_seconds=10,security_reviewer='sec',operations_reviewer='ops',now=102)
 def test_same_reviewer(self):
  with self.assertRaisesRegex(ReconciliationRBACError,'TWO_DISTINCT'):
   self.policy.configure(max_age_seconds=10,security_reviewer='sec',operations_reviewer='sec',now=102)
 def test_invalid_limit(self):
  with self.assertRaisesRegex(ReconciliationRBACError,'INVALID_POLICY'):
   self.policy.configure(max_age_seconds=True,security_reviewer='sec',operations_reviewer='ops',now=102)
 def test_disabled_reviewer(self):
  self.apply(self.exp(ops=False))
  with self.assertRaisesRegex(ReconciliationRBACError,'NOT_AUTHORIZED'):
   self.policy.configure(max_age_seconds=10,security_reviewer='sec',operations_reviewer='ops',now=102)
 def test_future_snapshot(self):
  self.apply()
  with self.assertRaisesRegex(ReconciliationRBACError,'FUTURE_DIRECTORY'):
   self.policy.configure(max_age_seconds=10,security_reviewer='sec',operations_reviewer='ops',now=100)
 def test_clock_regression(self):
  self.setup_policy()
  with self.assertRaisesRegex(ReconciliationRBACError,'CLOCK_REGRESSION'):
   self.policy.configure(max_age_seconds=10,security_reviewer='sec',operations_reviewer='ops',now=101)
 def test_audit_tamper(self):
  self.setup_policy();self.a.execute("UPDATE ldaps_freshness_policy_audit SET new_limit=999")
  with self.assertRaisesRegex(ReconciliationRBACError,'TAMPERED'):self.policy.verify()
 def test_state_tamper(self):
  self.setup_policy();self.a.execute('UPDATE ldaps_rbac_directory_freshness SET max_age_seconds=999')
  with self.assertRaisesRegex(ReconciliationRBACError,'STATE_MISMATCH'):self.policy.verify()
 def test_decision_blocked_on_audit_tamper(self):
  self.setup_policy();self.a.execute("UPDATE ldaps_freshness_policy_audit SET new_limit=999")
  with self.assertRaisesRegex(ReconciliationRBACError,'TAMPERED'):self.decide('sec')
 def test_atomic_rollback(self):
  self.apply();self.a.execute("CREATE TRIGGER fail_policy BEFORE INSERT ON ldaps_freshness_policy_audit BEGIN SELECT RAISE(ABORT,'failure'); END")
  with self.assertRaises(sqlite3.IntegrityError):
   self.policy.configure(max_age_seconds=10,security_reviewer='sec',operations_reviewer='ops',now=102)
  self.assertIsNone(self.a.execute('SELECT * FROM ldaps_rbac_directory_freshness').fetchone())
 def test_restart_instance(self):
  self.setup_policy();self.assertEqual(AuditedFreshnessPolicy(self.rbac).verify()['events'],1)
