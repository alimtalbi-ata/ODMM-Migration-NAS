"""V183.9 regression tests: legacy freshness API cannot bypass audited policy."""
import unittest
from unittest.mock import Mock
import sqlite3
from ldaps_directory_freshness import DirectoryFreshnessPolicy
from ldaps_rbac_reconciliation import ReconciliationRBACError

class FreshnessBypassGuardTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:',isolation_level=None)
        self.rbac=Mock();self.rbac.db=self.db
        self.policy=DirectoryFreshnessPolicy(self.rbac)
    def tearDown(self):self.db.close()
    def test_legacy_configuration_rejected_when_audit_installed(self):
        self.db.execute('CREATE TABLE ldaps_freshness_policy_audit (seq INTEGER, at INTEGER, security_reviewer TEXT, operations_reviewer TEXT, previous_limit INTEGER, new_limit INTEGER, synced_at INTEGER, directory_generation INTEGER, previous_hash TEXT, event_hash TEXT)')
        with self.assertRaises(ReconciliationRBACError) as ctx:self.policy.configure(max_age_seconds=5)
        self.assertEqual(str(ctx.exception),'AUDITED_POLICY_REQUIRED')
        self.assertFalse(self.db.in_transaction)
    def test_legacy_configuration_rejected_with_existing_audit_events(self):
        self.db.execute('CREATE TABLE ldaps_freshness_policy_audit (seq INTEGER, at INTEGER, security_reviewer TEXT, operations_reviewer TEXT, previous_limit INTEGER, new_limit INTEGER, synced_at INTEGER, directory_generation INTEGER, previous_hash TEXT, event_hash TEXT)')
        with self.assertRaises(ReconciliationRBACError):self.policy.configure(max_age_seconds=100)
    def test_invalid_parameters_still_rejected(self):
        with self.assertRaises(ReconciliationRBACError):self.policy.configure(max_age_seconds=-1)
    def test_guard_survives_reopen(self):
        import tempfile,os
        with tempfile.TemporaryDirectory() as tmp:
            path=os.path.join(tmp,'policy.db')
            a=sqlite3.connect(path,isolation_level=None)
            a.execute('CREATE TABLE ldaps_freshness_policy_audit (seq INTEGER, at INTEGER, security_reviewer TEXT, operations_reviewer TEXT, previous_limit INTEGER, new_limit INTEGER, synced_at INTEGER, directory_generation INTEGER, previous_hash TEXT, event_hash TEXT)');a.close()
            b=sqlite3.connect(path,isolation_level=None)
            r=Mock();r.db=b
            with self.assertRaises(ReconciliationRBACError):DirectoryFreshnessPolicy(r).configure(max_age_seconds=1)
            b.close()

if __name__=='__main__':unittest.main()
