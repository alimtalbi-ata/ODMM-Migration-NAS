import tempfile
import sqlite3
import unittest
from pathlib import Path
from native_rotation_access_audit import AccessAudit
from native_rotation_audited_execution import execute_audited_rotation

class AuditedExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.audit=AccessAudit(Path(self.tmp.name)/'access.db',key=b'x'*32)
        self.calls=[]
    def run_rotation(self, rid='r1', auth=lambda:True, effect=None, subject='operator'):
        if effect is None: effect=lambda:self.calls.append('effect') or {'ok':True}
        return execute_audited_rotation(audit=self.audit,request_id=rid,subject=subject,
                    target_key_id='key2',authorize=auth,execute=effect)
    def test_success_and_order(self):
        def effect():
            self.assertEqual(self.audit.verify()['count'],1)
            return 42
        self.assertEqual(self.run_rotation(effect=effect),42)
        self.assertEqual(self.audit.verify()['count'],2)
    def test_no_replay_after_success(self):
        self.run_rotation()
        with self.assertRaisesRegex(ValueError,'ALREADY_ADMITTED'):self.run_rotation()
        self.assertEqual(len(self.calls),1)
    def test_no_replay_after_crash(self):
        def crash():raise RuntimeError('connection lost')
        with self.assertRaises(RuntimeError):self.run_rotation(effect=crash)
        with self.assertRaisesRegex(ValueError,'ALREADY_ADMITTED'):self.run_rotation()
        self.assertEqual(self.audit.verify()['count'],2)
    def test_authorization_denied(self):
        with self.assertRaisesRegex(ValueError,'NOT_AUTHORIZED'):self.run_rotation(auth=lambda:False)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.audit.verify()['count'],1)
    def test_audit_failure_blocks_effect(self):
        self.audit.append({'event_id':'x','event':'rotation_access_denied'})
        with sqlite3.connect(self.audit.path) as db:
            db.execute("UPDATE access_audit SET signature='BAD' WHERE seq=1")
        with self.assertRaises(Exception):self.run_rotation()
        self.assertEqual(self.calls,[])
    def test_conflicting_request(self):
        self.run_rotation()
        with self.assertRaisesRegex(ValueError,'REQUEST_CONFLICT'):self.run_rotation(subject='different')
    def test_invalid_id(self):
        with self.assertRaisesRegex(ValueError,'ID_INVALID'):self.run_rotation(rid='../escape')
    def test_restart_requires_reconciliation(self):
        self.run_rotation()
        head=self.audit.verify()['head']
        self.audit=AccessAudit(self.audit.path,key=b'x'*32,expected_head=head)
        with self.assertRaisesRegex(ValueError,'ALREADY_ADMITTED'):self.run_rotation()
    def test_missing_anchor_fails_closed(self):
        self.audit.expected_head='0'*64
        with self.assertRaisesRegex(ValueError,'HEAD_MISMATCH'):self.run_rotation()
