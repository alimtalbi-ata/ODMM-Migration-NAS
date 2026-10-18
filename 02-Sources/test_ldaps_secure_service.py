import threading
import unittest
from test_ldaps_dual_control_admin import DualControlTests
from ldaps_secure_service import SecureRoleService
from ldaps_transition_reconciliation import TransitionReconciliationError

class SecureServiceTests(DualControlTests):
    def setUp(self):
        super().setUp()
        self.service=SecureRoleService(self.admin)
    def request(self,sec='s1',ops='o1',target='target'):
        return self.service.set_role(security_token=self.tok('reviewer',sec),
            operations_token=self.tok('operator',ops),target_subject=target,
            role='AUDITOR',enabled=True,now=150)
    def test_requires_dual_admin(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'DUAL_CONTROL_REQUIRED'):
            SecureRoleService(self.gate)
    def test_authorized_change(self):
        self.assertEqual(self.request()['service_boundary'],'DUAL_CONTROL_ONLY')
    def test_no_cutover(self):
        self.assertFalse(self.request()['cutover_authorized'])
    def test_no_execution(self):
        self.assertFalse(self.request()['execution_authorized'])
    def test_no_legacy_provision(self):
        with self.assertRaises(AttributeError):self.service.provision
    def test_no_legacy_recover(self):
        with self.assertRaises(AttributeError):self.service.recover
    def test_no_admin_exposure(self):
        with self.assertRaises(AttributeError):self.service.admin
    def test_audit(self):
        self.request()
        self.assertEqual(self.service.audit_status()['events'],1)
    def test_replay(self):
        self.request()
        with self.assertRaisesRegex(TransitionReconciliationError,'REPLAY'):
            self.request(target='another')
    def test_concurrent_same_token_exactly_one(self):
        outcomes=[]
        def worker():
            try:self.request();outcomes.append('ok')
            except Exception:outcomes.append('denied')
        ts=[threading.Thread(target=worker) for _ in range(6)]
        for t in ts:t.start()
        for t in ts:t.join()
        # SQLite's default same-thread rule rejects cross-thread use: fail closed.
        self.assertEqual(outcomes.count('ok'),0)
        self.assertEqual(self.service.audit_status()['events'],0)
        self.request()
        self.assertEqual(self.service.audit_status()['events'],1)
    def test_independent_pairs(self):
        self.request()
        self.assertEqual(self.request('s2','o2','target2')['status'],'DUAL_CONTROL_GRANT_UPDATED')
    def test_revocation_blocks(self):
        self.registry.revoke(kind='token',identifier='o1',now=100)
        with self.assertRaises(Exception):self.request()
    def test_missing_ops_role(self):
        self.gate.provision(issuer=self.gate.verifier.issuer,subject='operator',role='OPERATIONS',enabled=False)
        with self.assertRaisesRegex(TransitionReconciliationError,'ROLE_REQUIRED'):self.request()
