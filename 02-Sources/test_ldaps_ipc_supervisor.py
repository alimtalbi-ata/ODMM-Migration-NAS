import os
import socket
import tempfile
import unittest
from pathlib import Path
from ldaps_ipc_boundary import IPCBoundaryError
from ldaps_ipc_supervisor import AuditIPCSupervisor

class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'service.sock'
        self.s=AuditIPCSupervisor(self.path,expected_uid=os.getuid(),max_heartbeat_age=10)
    def tearDown(self):self.tmp.cleanup()
    def test_absent(self):self.assertEqual(self.s.inspect(now=100)['status'],'SOCKET_ABSENT')
    def test_invalid_uid(self):
        with self.assertRaises(IPCBoundaryError):AuditIPCSupervisor(self.path,expected_uid=True)
    def test_invalid_age(self):
        with self.assertRaises(IPCBoundaryError):AuditIPCSupervisor(self.path,expected_uid=0,max_heartbeat_age=0)
    def test_invalid_time(self):
        with self.assertRaises(IPCBoundaryError):self.s.inspect(now=-1)
    def test_file_not_socket(self):
        self.path.touch()
        self.assertEqual(self.s.inspect()['status'],'PATH_NOT_SOCKET_MANUAL_REVIEW')
    def test_missing_confirmation(self):
        with self.assertRaises(IPCBoundaryError):self.s.confirm_stale(report=self.s.inspect(),operator_confirmed=False)
    def test_tamper(self):
        r=self.s.inspect();r['status']='OTHER'
        with self.assertRaisesRegex(IPCBoundaryError,'TAMPERED'):self.s.confirm_stale(report=r,operator_confirmed=True)
    def test_replacement(self):
        self.path.touch();r=self.s.inspect();self.path.unlink();self.path.write_text('new')
        with self.assertRaisesRegex(IPCBoundaryError,'SOCKET_CHANGED'):self.s.confirm_stale(report=r,operator_confirmed=True)
    def test_manual_review_does_not_remove(self):
        self.path.touch();r=self.s.inspect();v=self.s.confirm_stale(report=r,operator_confirmed=True)
        self.assertEqual(v['status'],'MANUAL_INVESTIGATION_REQUIRED');self.assertTrue(self.path.exists())
    @unittest.skipUnless(hasattr(socket,'AF_UNIX'),'Unix sockets unavailable')
    def test_socket_present(self):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(self.path));os.chmod(self.path,0o600)
            self.assertEqual(self.s.inspect()['status'],'SOCKET_PRESENT_LIVENESS_UNVERIFIED')
            with self.assertRaisesRegex(IPCBoundaryError,'SOCKET_NOT_STALE'):
                self.s.confirm_stale(report=self.s.inspect(),operator_confirmed=True)
    def test_report_stable(self):
        self.assertEqual(self.s.inspect(now=100),self.s.inspect(now=100))
    def test_scope_change(self):
        r=self.s.inspect();other=AuditIPCSupervisor(self.path,expected_uid=os.getuid()+1)
        with self.assertRaisesRegex(IPCBoundaryError,'SCOPE_CHANGED'):
            other.confirm_stale(report=r,operator_confirmed=True)
