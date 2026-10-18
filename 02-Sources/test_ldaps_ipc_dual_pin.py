import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from ldaps_ipc_persistent_identity import PersistentProcessIdentity, IdentityPinError
from ldaps_ipc_dual_pin import DualPinController

class DualPinTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name);self.guard=Mock();self.guard.digest='a'*64
        self.guard.check.return_value={'status':'PEER_PROCESS_VERIFIED','peer_pid':11,'process_start_ticks':22}
        self.pin=PersistentProcessIdentity(self.guard,pin_path=root/'pin',key=b'p'*32)
        self.pin.enroll(operator_confirmed=True,expected_pid=11,expected_start_ticks=22)
        self.ctrl=DualPinController(self.pin,gate_path=root/'gate.db',key=b'a'*32)
    def change_peer(self):
        self.guard.check.return_value={'status':'PEER_PROCESS_VERIFIED','peer_pid':33,'process_start_ticks':44}
    def rotate(self,**kwargs):
        return self.ctrl.rotate(security_reviewer='sec',operations_reviewer='ops',operator_confirmed=True,expected_pid=33,expected_start_ticks=44,**kwargs)
    def test_rotation(self):
        self.change_peer();self.assertEqual(self.rotate()['status'],'DUAL_PIN_ROTATED')
        self.assertEqual(self.pin.check()['status'],'PERSISTENT_PEER_VERIFIED')
    def test_audit_reopen(self):
        self.change_peer();self.rotate();self.assertEqual(self.ctrl.verify_audit()['status'],'PIN_AUDIT_VERIFIED')
    def test_no_confirmation(self):
        self.change_peer()
        with self.assertRaises(IdentityPinError):self.ctrl.rotate(security_reviewer='sec',operations_reviewer='ops',operator_confirmed=False,expected_pid=33,expected_start_ticks=44)
    def test_same_reviewer(self):
        self.change_peer()
        with self.assertRaises(IdentityPinError):self.ctrl.rotate(security_reviewer='sec',operations_reviewer='sec',operator_confirmed=True,expected_pid=33,expected_start_ticks=44)
    def test_missing_reviewer(self):
        self.change_peer()
        with self.assertRaises(IdentityPinError):self.ctrl.rotate(security_reviewer='',operations_reviewer='ops',operator_confirmed=True,expected_pid=33,expected_start_ticks=44)
    def test_wrong_peer(self):
        with self.assertRaises(IdentityPinError):self.rotate()
    def test_audit_tamper(self):
        self.change_peer();self.rotate()
        with sqlite3.connect(self.ctrl.gate_path) as db:db.execute("UPDATE pin_audit SET event='{}' WHERE seq=1")
        with self.assertRaises(IdentityPinError):self.ctrl.verify_audit()
    def test_gate_collision(self):
        with self.assertRaises(IdentityPinError):DualPinController(self.pin,gate_path=self.pin.path,key=b'a'*32)
    def test_short_key(self):
        with self.assertRaises(IdentityPinError):DualPinController(self.pin,gate_path='unused',key=b'a')
    def test_interrupted_rotation_blocks_retry(self):
        self.change_peer()
        original=self.pin.rotate
        self.pin.rotate=Mock(side_effect=OSError('disk full'))
        with self.assertRaises(OSError):self.rotate()
        self.pin.rotate=original
        with self.assertRaisesRegex(IdentityPinError,'PENDING_ROTATION_MANUAL_REVIEW'):self.rotate()
    def test_no_automatic_execution(self):
        self.change_peer();result=self.rotate()
        self.assertFalse(result['execution_authorized']);self.assertFalse(result['cutover_authorized'])
    def test_duplicate_rotation(self):
        self.change_peer();self.rotate()
        with self.assertRaises(IdentityPinError):self.rotate()
