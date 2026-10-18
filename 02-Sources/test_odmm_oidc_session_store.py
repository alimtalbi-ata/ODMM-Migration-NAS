import tempfile
import unittest
from pathlib import Path
from odmm_oidc_session_store import SQLiteOIDCStore
from odmm_operations_security import Principal

class SessionStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.t=[1000]
        self.path=Path(self.tmp.name)/'sessions.db'
        self.a=SQLiteOIDCStore(self.path,clock=lambda:self.t[0])
        self.b=SQLiteOIDCStore(self.path,clock=lambda:self.t[0])
    def tearDown(self): self.tmp.cleanup()
    def test_single_use_across_connections(self):
        self.a.put_pending('state','nonce','pkce',1100)
        self.assertEqual(self.b.consume_pending('state'),('nonce','pkce',1100))
        self.assertIsNone(self.a.consume_pending('state'))
    def test_expired_pending(self):
        self.a.put_pending('state','nonce','pkce',999)
        self.assertIsNone(self.b.consume_pending('state'))
    def test_cross_instance_session(self):
        self.a.put_session('hash',Principal('alice',frozenset({'viewer'}),True),1100)
        self.assertEqual(self.b.get_session('hash').subject,'alice')
        self.b.delete_session('hash')
        self.assertIsNone(self.a.get_session('hash'))
    def test_expiration(self):
        self.a.put_session('hash',Principal('alice',frozenset({'viewer'}),True),1001)
        self.t[0]=1002
        self.assertIsNone(self.b.get_session('hash'))
        self.assertEqual(self.a.cleanup(),(0,1))
    def test_reject_unverified(self):
        with self.assertRaises(PermissionError):
            self.a.put_session('hash',Principal('alice',frozenset({'viewer'}),False),1100)
    def test_file_mode(self):
        import os
        if os.name=='posix': self.assertEqual(self.path.stat().st_mode & 0o777,0o600)

if __name__=='__main__': unittest.main()
