import unittest
from test_ldaps_directory_rbac_bridge import Tests as OriginalTests
import sqlite3
from ldaps_crash_reconciliation import CrashReconciliationLedger
from ldaps_durable_target import DurableFencedTarget
from ldaps_rbac_reconciliation import ReconciliationRBAC
from ldaps_directory_rbac_bridge import DirectoryRBACBridge
class C:
 def __init__(self,db):self.db=db
class Base:
 setUp=OriginalTests.setUp
 tearDown=OriginalTests.tearDown
 exp=OriginalTests.exp
 apply=OriginalTests.apply
 decide=OriginalTests.decide
from ldaps_directory_freshness import DirectoryFreshnessPolicy
from ldaps_rbac_reconciliation import ReconciliationRBACError

class FreshnessTests(Base):
 def setUp(self):
  super().setUp();self.policy=DirectoryFreshnessPolicy(self.rbac)
 def test_requires_snapshot(self):
  with self.assertRaisesRegex(ReconciliationRBACError,'SNAPSHOT_REQUIRED'):self.policy.configure(max_age_seconds=10)
 def test_rejects_bool(self):
  with self.assertRaisesRegex(ReconciliationRBACError,'INVALID_DIRECTORY_MAX_AGE'):self.policy.configure(max_age_seconds=True)
 def test_rejects_negative(self):
  with self.assertRaisesRegex(ReconciliationRBACError,'INVALID_DIRECTORY_MAX_AGE'):self.policy.configure(max_age_seconds=-1)
 def test_fresh(self):
  self.apply();self.policy.configure(max_age_seconds=10);self.assertEqual(self.policy.assess(now=110)['status'],'FRESH')
 def test_stale(self):
  self.apply();self.policy.configure(max_age_seconds=0);self.assertEqual(self.policy.assess(now=102)['status'],'STALE')
 def test_stale_blocks_decision(self):
  self.apply();self.policy.configure(max_age_seconds=0)
  with self.assertRaisesRegex(ReconciliationRBACError,'STALE_FAIL_CLOSED'):self.decide('sec')
 def test_fresh_allows_decision(self):
  self.apply();self.policy.configure(max_age_seconds=10);self.assertFalse(self.decide('sec')['review_complete'])
 def test_future_snapshot_blocks(self):
  self.apply();self.policy.configure(max_age_seconds=10)
  with self.assertRaisesRegex(ReconciliationRBACError,'STALE_FAIL_CLOSED'):self.rbac.decide('e','r',observation_hash=self.obs['evidence_sha256'],reviewer='sec',action='BLOCK',decided_at=100)
 def test_refresh_resets_age(self):
  x=self.apply();self.policy.configure(max_age_seconds=0)
  self.bridge.apply(self.exp('v2'),now=102,expected_previous_digest=x['snapshot_sha256'])
  self.assertEqual(self.policy.assess(now=102)['status'],'FRESH')
 def test_unchanged_grants_still_age(self):
  self.apply();self.policy.configure(max_age_seconds=1);self.assertFalse(self.policy.assess(now=103)['review_allowed'])
 def test_policy_survives_new_instance(self):
  self.apply();self.policy.configure(max_age_seconds=5);self.assertEqual(DirectoryFreshnessPolicy(self.rbac).assess(now=105)['status'],'FRESH')
 def test_bad_timestamp(self):
  with self.assertRaisesRegex(ReconciliationRBACError,'INVALID_TIMESTAMP'):self.policy.assess(now=True)
 def test_unconfigured_blocks_assessment(self):self.assertFalse(self.policy.assess(now=101)['review_allowed'])
 def test_no_execution_authorization(self):
  self.apply();self.assertFalse(self.policy.configure(max_age_seconds=10)['execution_authorized'])
 def test_audit_tamper_blocks_policy(self):
  self.apply();self.a.execute("UPDATE ldaps_rbac_grant_audit SET changed='bad'")
  with self.assertRaisesRegex(ReconciliationRBACError,'TAMPERED'):self.policy.configure(max_age_seconds=10)
