import hashlib
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from ldaps_ipc_process_guard import ProcessGuard

@unittest.skipUnless(os.name == 'posix' and hasattr(socket, 'SO_PEERCRED') and Path('/proc/self/stat').exists(), 'Linux /proc required')
class ProcessGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'s.sock'
        with open('/proc/self/exe','rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
        self.guard=ProcessGuard(self.path, expected_uid=os.geteuid(), expected_exe_sha256=digest)
    def tearDown(self): self.tmp.cleanup()
    def serve(self):
        server=socket.socket(socket.AF_UNIX);server.bind(str(self.path));os.chmod(self.path,0o600);server.listen(1)
        def worker():
            try:
                conn,_=server.accept()
                with conn:
                    conn.recv(1024)
                    try:conn.sendall(b'{"status":"OK","audit":{},"execution_authorized":false,"cutover_authorized":false}\n')
                    except BrokenPipeError:pass
            finally:server.close()
        t=threading.Thread(target=worker,daemon=True);t.start();return t
    def test_absent(self):self.assertEqual(self.guard.check()['status'],'SOCKET_ABSENT')
    def test_valid(self):
        t=self.serve();r=self.guard.check();t.join(2)
        self.assertEqual(r['status'],'PEER_PROCESS_VERIFIED');self.assertFalse(r['cutover_authorized'])
    def test_wrong_digest(self):
        self.guard.digest='0'*64;t=self.serve();r=self.guard.check();t.join(2)
        self.assertEqual(r['status'],'EXECUTABLE_DIGEST_MISMATCH')
    def test_repeated(self):
        t=self.serve();self.assertEqual(self.guard.check()['status'],'PEER_PROCESS_VERIFIED');t.join(2)
        self.path.unlink();t=self.serve();self.assertEqual(self.guard.check()['status'],'PEER_PROCESS_VERIFIED');t.join(2)
    def test_pid_restart_detected(self):
        self.guard.last_identity=(999999,1)
        t=self.serve();r=self.guard.check();t.join(2)
        self.assertEqual(r['status'],'PEER_RESTART_REVIEW_REQUIRED')
    def test_restart_requires_confirmation(self):
        with self.assertRaises(ValueError):self.guard.accept_restart(operator_confirmed=False)
    def test_restart_reset(self):
        self.guard.last_identity=(10,20)
        self.assertEqual(self.guard.accept_restart(operator_confirmed=True)['status'],'RESTART_BASELINE_RESET')
        self.assertIsNone(self.guard.last_identity)
    def test_bad_digest(self):
        for value in ('x', 'A'*64, None):
            with self.assertRaises(ValueError):ProcessGuard(self.path,expected_uid=0,expected_exe_sha256=value)
    def test_process_invalid_pid(self):
        for pid in (-1,0,True,'12'):
            with self.assertRaises(ValueError):ProcessGuard._process(pid)
    def test_process_missing(self):
        with self.assertRaises(OSError):ProcessGuard._process(999999999)
    def test_evidence_unavailable(self):
        t=self.serve()
        with patch.object(ProcessGuard,'_process',side_effect=OSError('missing')):
            r=self.guard.check()
        t.join(2);self.assertEqual(r['status'],'PROCESS_EVIDENCE_UNAVAILABLE')
    def test_digest_does_not_set_baseline(self):
        self.guard.digest='0'*64;t=self.serve();self.guard.check();t.join(2)
        self.assertIsNone(self.guard.last_identity)
