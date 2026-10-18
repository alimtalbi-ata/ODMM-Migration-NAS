"""V198.3 session-bound CSRF tests. Author: Abdelhalim Talbi."""
import tempfile,unittest
from pathlib import Path
from odmm_oidc_session_store import SQLiteOIDCStore
from odmm_operations_security import Principal
class BindingTests(unittest.TestCase):
 def test_binding_and_logout(self):
  with tempfile.TemporaryDirectory() as d:
   store=SQLiteOIDCStore(Path(d)/'sessions.db')
   store.put_session('sid-a',Principal('alice',frozenset({'viewer'}),verified=True),9999999999)
   store.put_session('sid-b',Principal('bob',frozenset({'viewer'}),verified=True),9999999999)
   store.bind_csrf('sid-a','token-a');store.bind_csrf('sid-b','token-b')
   self.assertTrue(store.verify_csrf('sid-a','token-a'))
   self.assertFalse(store.verify_csrf('sid-b','token-a'))
   self.assertFalse(store.verify_csrf('sid-a','token-b'))
   store.delete_session('sid-a')
   self.assertFalse(store.verify_csrf('sid-a','token-a'))
 def test_restart_persistence(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'sessions.db';store=SQLiteOIDCStore(path)
   store.put_session('sid',Principal('alice',frozenset(),verified=True),9999999999)
   store.bind_csrf('sid','token')
   self.assertTrue(SQLiteOIDCStore(path).verify_csrf('sid','token'))
if __name__=='__main__':unittest.main()
