import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from ldaps_ipc_boundary import LocalAuditIPC, IPCBoundaryError

class DummyService:
    def audit_status(self):
        return {'valid': True, 'events': 3}

@unittest.skipUnless(os.name == 'posix' and hasattr(socket, 'SO_PEERCRED') and hasattr(os, 'geteuid') and os.geteuid() != 0, 'requires unprivileged Linux')
class TestLocalAuditIPC(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o700)
        self.path = Path(self.tmp.name) / 'rbac.sock'
        self.ipc = LocalAuditIPC(DummyService(), socket_path=self.path, allowed_uids={os.geteuid()})
    def tearDown(self):
        self.tmp.cleanup()
    def exchange(self, request):
        listener = self.ipc.bind()
        def server():
            c, _ = listener.accept()
            with c:
                self.ipc.handle(c)
        t = threading.Thread(target=server)
        t.start()
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(str(self.path))
                client.sendall(request)
                data = client.recv(4096)
            return data
        finally:
            t.join(3)
            listener.close()
    def test_read_only_audit(self):
        self.assertIn(b'"status": "OK"', self.exchange(b'{"operation":"audit_status"}\n'))
    def test_mutation_refused(self):
        self.assertIn(b'DENIED', self.exchange(b'{"operation":"set_role"}\n'))
    def test_extra_fields_refused(self):
        self.assertIn(b'DENIED', self.exchange(b'{"operation":"audit_status","x":1}\n'))
    def test_oversize_refused(self):
        self.assertIn(b'DENIED', self.exchange(b'x'*1100+b'\n'))
    def test_existing_socket_refused(self):
        self.path.touch()
        with self.assertRaises(IPCBoundaryError): self.ipc.bind()
    def test_public_directory_refused(self):
        os.chmod(self.tmp.name, 0o755)
        with self.assertRaises(IPCBoundaryError): self.ipc.bind()
    def test_unauthorized_uid_refused(self):
        self.ipc = LocalAuditIPC(DummyService(), socket_path=self.path, allowed_uids={os.geteuid()+10000})
        self.assertIn(b'DENIED', self.exchange(b'{"operation":"audit_status"}\n'))

class TestConfiguration(unittest.TestCase):
    def test_empty_uids(self):
        with self.assertRaises(IPCBoundaryError): LocalAuditIPC(None, socket_path='/tmp/x', allowed_uids=set())
    def test_bool_uid(self):
        with self.assertRaises(IPCBoundaryError): LocalAuditIPC(None, socket_path='/tmp/x', allowed_uids={True})
    def test_invalid_limit(self):
        with self.assertRaises(IPCBoundaryError): LocalAuditIPC(None, socket_path='/tmp/x', allowed_uids={1000}, max_request=10)
