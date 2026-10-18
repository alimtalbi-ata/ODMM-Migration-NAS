import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ldaps_os_boundary import POSIXBoundaryAttestation, OSBoundaryError

@unittest.skipUnless(os.name=='posix' and os.geteuid()!=0,'non-root POSIX required')
class TestPOSIXBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'private'
        self.root.mkdir(mode=0o700)
        self.db=self.root/'rbac.sqlite'
        self.gate=self.root/'gate.sqlite'
        for p in (self.db,self.gate):
            p.touch(mode=0o600)
            p.chmod(0o600)
        self.check=POSIXBoundaryAttestation(database_path=self.db,gate_path=self.gate)
    def test_valid(self):
        self.assertEqual(self.check.verify()['status'],'POSIX_FILESYSTEM_BOUNDARY_VERIFIED')
    def test_no_cutover(self):
        self.assertFalse(self.check.verify()['cutover_authorized'])
    def test_directory_world_access(self):
        self.root.chmod(0o755)
        with self.assertRaises(OSBoundaryError):self.check.verify()
    def test_database_group_access(self):
        self.db.chmod(0o640)
        with self.assertRaises(OSBoundaryError):self.check.verify()
    def test_gate_world_access(self):
        self.gate.chmod(0o604)
        with self.assertRaises(OSBoundaryError):self.check.verify()
    def test_symlink_gate(self):
        self.gate.unlink();self.gate.symlink_to(self.db)
        with self.assertRaises(OSBoundaryError):self.check.verify()
    def test_sidecar_permissions(self):
        p=Path(str(self.db)+'-wal');p.touch();p.chmod(0o644)
        with self.assertRaises(OSBoundaryError):self.check.verify()
    def test_sidecar_symlink(self):
        p=Path(str(self.db)+'-shm');p.symlink_to(self.gate)
        with self.assertRaises(OSBoundaryError):self.check.verify()
    def test_wrong_uid(self):
        with self.assertRaises(OSBoundaryError):
            POSIXBoundaryAttestation(database_path=self.db,gate_path=self.gate,expected_uid=os.geteuid()+1).verify()
    def test_root_refused(self):
        with patch('ldaps_os_boundary.os.geteuid',return_value=0):
            with self.assertRaises(OSBoundaryError):self.check.verify()
    def test_missing_database(self):
        self.db.unlink()
        with self.assertRaises(OSBoundaryError):self.check.verify()
    def test_missing_gate(self):
        self.gate.unlink()
        with self.assertRaises(OSBoundaryError):self.check.verify()
    def test_sidecar_secure(self):
        p=Path(str(self.db)+'-journal');p.touch(mode=0o600);p.chmod(0o600)
        self.assertTrue(self.check.verify()['status'].endswith('VERIFIED'))
