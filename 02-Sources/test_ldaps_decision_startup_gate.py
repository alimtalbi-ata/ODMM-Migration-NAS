"""Regression tests: audited reviews cannot bypass the startup gate."""
import unittest
from unittest.mock import patch
from test_ldaps_freshness_policy_audit import Tests as Fixture
from ldaps_rbac_reconciliation import ReconciliationRBACError

class Tests(Fixture):
    def test_gate_invoked_for_audited_review(self):
        self.setup_policy()
        with patch('ldaps_security_startup.verify_startup', side_effect=ReconciliationRBACError('STARTUP_BLOCKED')) as gate:
            with self.assertRaisesRegex(ReconciliationRBACError,'STARTUP_BLOCKED'):
                self.decide('sec')
            gate.assert_called_once()
        self.assertEqual(self.a.execute('SELECT count(*) FROM ldaps_rbac_decisions').fetchone()[0],0)

    def test_stale_audited_snapshot_blocks_review(self):
        self.setup_policy()
        with self.assertRaisesRegex(ReconciliationRBACError,'DIRECTORY_POLICY_NOT_FRESH'):
            self.rbac.decide('ev','req',observation_hash='bogus',reviewer='sec',action='INVESTIGATE',decided_at=112)

    def test_future_audited_snapshot_blocks_review(self):
        self.setup_policy()
        with self.assertRaisesRegex(ReconciliationRBACError,'DIRECTORY_POLICY_NOT_FRESH'):
            self.rbac.decide('ev','req',observation_hash='bogus',reviewer='sec',action='INVESTIGATE',decided_at=100)

    def test_tampered_audited_policy_blocks_review(self):
        self.setup_policy()
        self.a.execute('UPDATE ldaps_freshness_policy_audit SET new_limit=999')
        with self.assertRaises(ReconciliationRBACError):
            self.rbac.decide('ev','req',observation_hash='bogus',reviewer='sec',action='INVESTIGATE',decided_at=105)

    def test_uninitialized_policy_is_legacy_compatibility(self):
        self.apply()
        with self.assertRaisesRegex(ReconciliationRBACError,'STALE_OBSERVATION'):
            self.rbac.decide('ev','req',observation_hash='bogus',reviewer='sec',action='INVESTIGATE',decided_at=105)

    def test_no_implicit_authorization(self):
        self.setup_policy()
        from ldaps_security_startup import verify_startup
        result=verify_startup(self.rbac,now=105)
        self.assertFalse(result['execution_authorized'])
        self.assertFalse(result['cutover_authorized'])
