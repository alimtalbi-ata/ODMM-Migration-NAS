import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from ldaps_ipc_persistent_identity import PersistentProcessIdentity, IdentityPinError

class PersistentIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'pin.json'
        self.guard=Mock()
        self.guard.digest='a'*64
        self.guard.check.return_value={'status':'PEER_PROCESS_VERIFIED','peer_pid':123,'process_start_ticks':456}
        self.pin=PersistentProcessIdentity(self.guard,pin_path=self.path,key=b'k'*32)
    def enroll(self): return self.pin.enroll(operator_confirmed=True,expected_pid=123,expected_start_ticks=456)
    def test_missing(self): self.assertEqual(self.pin.check()['status'],'PIN_MISSING_MANUAL_ENROLLMENT')
    def test_enroll_and_check(self):
        self.assertEqual(self.enroll()['status'],'PIN_ENROLLED')
        self.assertEqual(self.pin.check()['status'],'PERSISTENT_PEER_VERIFIED')
    def test_reopen(self):
        self.enroll()
        second=PersistentProcessIdentity(self.guard,pin_path=self.path,key=b'k'*32)
        self.assertEqual(second.check()['status'],'PERSISTENT_PEER_VERIFIED')
    def test_no_confirmation(self):
        with self.assertRaises(IdentityPinError): self.pin.enroll(operator_confirmed=False,expected_pid=123,expected_start_ticks=456)
    def test_identity_mismatch(self):
        with self.assertRaises(IdentityPinError): self.pin.enroll(operator_confirmed=True,expected_pid=124,expected_start_ticks=456)
    def test_wrong_key(self):
        self.enroll()
        wrong=PersistentProcessIdentity(self.guard,pin_path=self.path,key=b'z'*32)
        self.assertEqual(wrong.check()['status'],'PIN_EVIDENCE_INVALID_MANUAL_REVIEW')
    def test_tampering(self):
        self.enroll(); obj=json.loads(self.path.read_text());obj['record']['pid']=999
        self.path.write_text(json.dumps(obj))
        self.assertEqual(self.pin.check()['status'],'PIN_EVIDENCE_INVALID_MANUAL_REVIEW')
    def test_no_overwrite(self):
        self.enroll()
        with self.assertRaises(IdentityPinError): self.enroll()
    def test_changed_peer(self):
        self.enroll();self.guard.check.return_value={'status':'PEER_PROCESS_VERIFIED','peer_pid':123,'process_start_ticks':999}
        self.assertEqual(self.pin.check()['status'],'PEER_CHANGED_MANUAL_REVIEW')
    def test_peer_unavailable(self):
        self.enroll();self.guard.check.return_value={'status':'SOCKET_ABSENT'}
        self.assertEqual(self.pin.check()['status'],'SOCKET_ABSENT')
    def test_symlink(self):
        target=Path(self.temp.name)/'other';target.write_text('hello');self.path.symlink_to(target)
        self.assertEqual(self.pin.check()['status'],'PIN_EVIDENCE_INVALID_MANUAL_REVIEW')
    def test_rotation(self):
        self.enroll();self.guard.check.return_value={'status':'PEER_PROCESS_VERIFIED','peer_pid':234,'process_start_ticks':567}
        self.assertEqual(self.pin.rotate(operator_confirmed=True,expected_pid=234,expected_start_ticks=567)['status'],'PIN_ROTATED')
        self.assertEqual(self.pin.check()['status'],'PERSISTENT_PEER_VERIFIED')
    def test_rotation_rejects_bad_identity(self):
        self.enroll()
        with self.assertRaises(IdentityPinError): self.pin.rotate(operator_confirmed=True,expected_pid=222,expected_start_ticks=456)
    def test_bad_key(self):
        with self.assertRaises(IdentityPinError):PersistentProcessIdentity(self.guard,pin_path=self.path,key=b'weak')
