import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from ldaps_ipc_boundary import LocalAuditIPC, IPCBoundaryError
from ldaps_ipc_lifecycle import AuditIPCLifecycle

class Dummy:
    def audit_status(self): return {'integrity':'OK'}

class TestConfig(unittest.TestCase):
    def test_invalid_backlog(self):
        with self.assertRaises(IPCBoundaryError): AuditIPCLifecycle(None, backlog=0)
    def test_bool_backlog(self):
        with self.assertRaises(IPCBoundaryError): AuditIPCLifecycle(None, backlog=True)
    def test_invalid_timeout(self):
        with self.assertRaises(IPCBoundaryError): AuditIPCLifecycle(None, accept_timeout=0)
    def test_bool_timeout(self):
        with self.assertRaises(IPCBoundaryError): AuditIPCLifecycle(None, accept_timeout=True)
    def test_not_started(self):
        with self.assertRaises(IPCBoundaryError): AuditIPCLifecycle(None).serve()
    def test_invalid_limit(self):
        with self.assertRaises(IPCBoundaryError): AuditIPCLifecycle(None).serve(max_connections=-1)

@unittest.skipUnless(os.name=='posix' and hasattr(socket,'SO_PEERCRED') and hasattr(os,'geteuid') and os.geteuid()!=0, 'requires unprivileged Linux')
class TestLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        os.chmod(self.temp.name,0o700)
        self.path=Path(self.temp.name)/'audit.sock'
        self.boundary=LocalAuditIPC(Dummy(),socket_path=self.path,allowed_uids={os.geteuid()})
        self.life=AuditIPCLifecycle(self.boundary,accept_timeout=.03)
    def tearDown(self):
        if self.life._listener is not None:
            try:self.life.stop()
            except IPCBoundaryError:pass
        self.temp.cleanup()
    def test_clean_start_stop_restart(self):
        self.life.start()
        with self.assertRaises(IPCBoundaryError):self.life.start()
        self.assertEqual(self.life.stop()['status'],'STOPPED_CLEAN')
        self.assertFalse(self.path.exists())
        self.life.start()
        self.assertEqual(self.life.stop()['status'],'STOPPED_CLEAN')
    def test_read_only_exchange(self):
        self.life.start()
        t=threading.Thread(target=lambda:self.life.serve(max_connections=1))
        t.start()
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(self.path))
            client.sendall(b'{"operation":"audit_status"}\n')
            self.assertIn(b'"status": "OK"',client.recv(4096))
        t.join(2)
        self.assertFalse(t.is_alive())
        self.life.stop()
    def test_mutation_refused(self):
        self.life.start()
        t=threading.Thread(target=lambda:self.life.serve(max_connections=1));t.start()
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(self.path));client.sendall(b'{"operation":"set_role"}\n')
            self.assertIn(b'DENIED',client.recv(4096))
        t.join(2);self.life.stop()
    def test_stale_socket_not_deleted(self):
        self.path.touch()
        with self.assertRaises(IPCBoundaryError):self.life.start()
        self.assertTrue(self.path.exists())
    def test_replaced_socket_not_deleted(self):
        self.life.start()
        self.path.unlink();self.path.write_text('replacement')
        with self.assertRaisesRegex(IPCBoundaryError,'SOCKET_REPLACED'):self.life.stop()
        self.assertEqual(self.path.read_text(),'replacement')
    def test_missing_socket_requires_review(self):
        self.life.start();self.path.unlink()
        with self.assertRaisesRegex(IPCBoundaryError,'SOCKET_DISAPPEARED'):self.life.stop()
    def test_stop_before_start(self):
        self.assertEqual(self.life.stop()['status'],'NOT_RUNNING')
