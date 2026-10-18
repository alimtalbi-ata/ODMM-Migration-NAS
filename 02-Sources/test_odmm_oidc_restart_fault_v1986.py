"""V198.6 restart, expiry and outage boundary regression tests."""
import tempfile
import unittest
from pathlib import Path
from odmm_oidc_session_store import SQLiteOIDCStore
from odmm_operations_security import Principal

class SessionRestartFaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'session.db'
        self.t=[1000.0]
        self.store=lambda: SQLiteOIDCStore(self.path,clock=lambda:self.t[0])
        self.p=Principal('operator',frozenset({'reader'}),verified=True)
    def test_session_survives_process_restart(self):
        s=self.store();s.put_session('session-hash',self.p,1100);s.bind_csrf('session-hash','csrf-secret')
        reloaded=self.store()
        self.assertEqual(reloaded.get_session('session-hash').subject,'operator')
        self.assertTrue(reloaded.verify_csrf('session-hash','csrf-secret'))
    def test_expiry_fails_closed_after_restart(self):
        s=self.store();s.put_session('session-hash',self.p,1001);s.bind_csrf('session-hash','csrf-secret')
        self.t[0]=1002
        self.assertIsNone(self.store().get_session('session-hash'))
        self.assertFalse(self.store().verify_csrf('session-hash','csrf-secret'))
    def test_logout_persists_across_restart(self):
        s=self.store();s.put_session('session-hash',self.p,1100);s.bind_csrf('session-hash','csrf-secret')
        s.delete_session('session-hash')
        self.assertIsNone(self.store().get_session('session-hash'))
        self.assertFalse(self.store().verify_csrf('session-hash','csrf-secret'))
    def test_state_replay_rejected_after_restart(self):
        self.store().put_pending('state','nonce','pkce',1100)
        self.assertIsNotNone(self.store().consume_pending('state'))
        self.assertIsNone(self.store().consume_pending('state'))
    def test_expired_state_rejected(self):
        self.store().put_pending('state','nonce','pkce',1001)
        self.t[0]=1002
        self.assertIsNone(self.store().consume_pending('state'))
    def test_unknown_session_rejected(self):
        self.assertIsNone(self.store().get_session('unknown'))
        self.assertFalse(self.store().verify_csrf('unknown','csrf-secret'))
    def test_wrong_csrf_rejected(self):
        s=self.store();s.put_session('session-hash',self.p,1100);s.bind_csrf('session-hash','csrf-secret')
        self.assertFalse(self.store().verify_csrf('session-hash','other'))
    def test_cleanup_expired_session_and_pending(self):
        s=self.store();s.put_session('session-hash',self.p,1001);s.bind_csrf('session-hash','csrf-secret');s.put_pending('state','nonce','pkce',1001)
        self.t[0]=1002
        self.assertEqual(self.store().cleanup(),(1,1))
        self.assertFalse(self.store().verify_csrf('session-hash','csrf-secret'))

if __name__=='__main__':unittest.main()
