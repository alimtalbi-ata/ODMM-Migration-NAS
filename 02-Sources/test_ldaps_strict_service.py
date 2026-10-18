import tempfile
from pathlib import Path
from test_ldaps_secure_service import SecureServiceTests
from ldaps_secure_service import SecureRoleService
from ldaps_transition_reconciliation import TransitionReconciliationError

class StrictServiceTests(SecureServiceTests):
    def setUp(self):
        super().setUp()
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.service=SecureRoleService(self.admin,gate_path=str(Path(self.tmp.name)/'gate.db'),strict=True)
    def test_missing_gate_denied(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'STRICT_SERVICE_GATE_REQUIRED'):
            SecureRoleService(self.admin,strict=True)
    def test_invalid_strict_denied(self):
        with self.assertRaisesRegex(TransitionReconciliationError,'INVALID_STRICT_MODE'):
            SecureRoleService(self.admin,strict='yes')
    def test_audit_before_and_after(self):
        self.assertEqual(self.service.audit_status()['events'],0)
        self.request()
        self.assertEqual(self.service.audit_status()['events'],1)
    def test_gate_contention_denies(self):
        from ldaps_service_concurrency import InterprocessServiceGate,ServiceConcurrencyError
        with InterprocessServiceGate(str(Path(self.tmp.name)/'gate.db'),timeout=0.01).exclusive():
            with self.assertRaisesRegex(ServiceConcurrencyError,'BUSY'):
                self.request()
