import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from ldaps_ipc_active_probe import ActiveAuditProbe
from ldaps_ipc_boundary import IPCBoundaryError

@unittest.skipUnless(os.name == 'posix' and hasattr(socket, 'SO_PEERCRED'), 'Linux required')
class ActiveProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'audit.sock'
        self.probe = ActiveAuditProbe(self.path, expected_uid=os.geteuid())
    def tearDown(self): self.tmp.cleanup()
    def serve(self, response):
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(self.path)); os.chmod(self.path, 0o600); server.listen(1)
        def worker():
            try:
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(2)
                    conn.recv(1024)
                    try: conn.sendall(response)
                    except BrokenPipeError: pass
            finally: server.close()
        t = threading.Thread(target=worker, daemon=True); t.start()
        return t
    def test_absent(self): self.assertEqual(self.probe.check()['status'], 'SOCKET_ABSENT')
    def test_regular_file(self):
        self.path.write_text('fake'); self.assertEqual(self.probe.check()['status'], 'PROBE_FAILED_MANUAL_REVIEW')
    def test_symlink(self):
        target = Path(self.tmp.name) / 'target'; target.write_text('x'); self.path.symlink_to(target)
        self.assertEqual(self.probe.check()['status'], 'PROBE_FAILED_MANUAL_REVIEW')
    def test_valid(self):
        t = self.serve(b'{"status":"OK","audit":{},"execution_authorized":false,"cutover_authorized":false}\n')
        result = self.probe.check(); t.join(2)
        self.assertEqual(result['status'], 'AUDIT_ENDPOINT_RESPONSIVE')
        self.assertFalse(result['automatic_cleanup'])
    def test_denied(self):
        t = self.serve(b'{"status":"DENIED"}\n'); self.assertEqual(self.probe.check()['status'], 'PROBE_FAILED_MANUAL_REVIEW'); t.join(2)
    def test_unsafe_flag(self):
        t = self.serve(b'{"status":"OK","audit":{},"execution_authorized":true,"cutover_authorized":false}\n')
        self.assertEqual(self.probe.check()['status'], 'PROBE_FAILED_MANUAL_REVIEW'); t.join(2)
    def test_extra_lines(self):
        t = self.serve(b'{"status":"OK","audit":{}}\n{}\n')
        self.assertEqual(self.probe.check()['status'], 'PROBE_FAILED_MANUAL_REVIEW'); t.join(2)
    def test_wrong_uid(self):
        other = ActiveAuditProbe(self.path, expected_uid=os.geteuid()+1)
        t = self.serve(b'{"status":"OK","audit":{}}\n')
        self.assertEqual(other.check()['status'], 'PROBE_FAILED_MANUAL_REVIEW')
        # No connection occurs when ownership fails; close server by connecting.
        with socket.socket(socket.AF_UNIX) as s: s.connect(str(self.path))
        t.join(2)
    def test_invalid_constructor(self):
        for uid in (-1, True, '1'):
            with self.assertRaises(IPCBoundaryError): ActiveAuditProbe(self.path, expected_uid=uid)
    def test_invalid_timeout(self):
        for value in (0, 11, True, -1):
            with self.assertRaises(IPCBoundaryError): ActiveAuditProbe(self.path, expected_uid=0, timeout=value)
    def test_invalid_limit(self):
        with self.assertRaises(IPCBoundaryError): ActiveAuditProbe(self.path, expected_uid=0, max_response=5)

if __name__ == '__main__': unittest.main()
