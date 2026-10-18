import tempfile
import unittest
from pathlib import Path
from test_ldaps_dual_control_admin import DualControlTests
from ldaps_secure_service import SecureRoleService
from ldaps_secure_startup import SecureStartupAttestation, SecureStartupError

class StartupTests(DualControlTests):
    def setUp(self):
        super().setUp()
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.service=SecureRoleService(self.admin,gate_path=str(Path(self.tmp.name)/'gate.db'),strict=True)
    def check(self,**kw):
        return SecureStartupAttestation(self.service,legacy_routes_exposed=False,direct_database_exposed=False,**kw).verify()
    def test_clean(self):self.assertEqual(self.check()['status'],'SECURE_STARTUP_VERIFIED')
    def test_no_execution(self):self.assertFalse(self.check()['execution_authorized'])
    def test_no_cutover(self):self.assertFalse(self.check()['cutover_authorized'])
    def test_legacy_exposure(self):
        with self.assertRaisesRegex(SecureStartupError,'UNSAFE_LEGACY_EXPOSURE'):
            SecureStartupAttestation(self.service,legacy_routes_exposed=True,direct_database_exposed=False).verify()
    def test_db_exposure(self):
        with self.assertRaisesRegex(SecureStartupError,'UNSAFE_LEGACY_EXPOSURE'):
            SecureStartupAttestation(self.service,legacy_routes_exposed=False,direct_database_exposed=True).verify()
    def test_strict_required(self):
        s=SecureRoleService(self.admin)
        with self.assertRaisesRegex(SecureStartupError,'STRICT_MODE_REQUIRED'):
            SecureStartupAttestation(s,legacy_routes_exposed=False,direct_database_exposed=False).verify()
    def test_boolean_declaration(self):
        with self.assertRaisesRegex(SecureStartupError,'EXPOSURE_DECLARATION_REQUIRED'):
            SecureStartupAttestation(self.service,legacy_routes_exposed=0,direct_database_exposed=False)
    def test_invalid_service(self):
        with self.assertRaisesRegex(SecureStartupError,'SECURE_SERVICE_REQUIRED'):
            SecureStartupAttestation(self.admin,legacy_routes_exposed=False,direct_database_exposed=False)
    def test_symlink_gate(self):
        link=Path(self.tmp.name)/'link.db'
        link.symlink_to(Path(self.tmp.name)/'real.db')
        s=SecureRoleService(self.admin,gate_path=str(link),strict=True)
        with self.assertRaisesRegex(SecureStartupError,'UNSAFE_GATE_PATH'):
            SecureStartupAttestation(s,legacy_routes_exposed=False,direct_database_exposed=False).verify()
    def test_audit_corruption(self):
        self.admin.db.execute("INSERT INTO oidc_dual_control_events VALUES (1,'a','b','c','AUDITOR',1,'x','y',1,'0','bad')")
        with self.assertRaises(Exception):self.check()
