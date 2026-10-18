import tempfile,unittest,concurrent.futures
from pathlib import Path
from odmm_oidc_session_store import SQLiteOIDCStore
from odmm_operations_security import Principal

class StoreConcurrencyTests(unittest.TestCase):
 def test_atomic_consume(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'oidc.db'; store=SQLiteOIDCStore(path,clock=lambda:100)
   store.put_pending('state','nonce','pkce',200)
   def consume(_): return SQLiteOIDCStore(path,clock=lambda:100).consume_pending('state')
   with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
    results=list(pool.map(consume,range(30)))
   self.assertEqual(sum(x is not None for x in results),1)
 def test_csrf_expiry_and_logout(self):
  with tempfile.TemporaryDirectory() as d:
   now=[100];store=SQLiteOIDCStore(Path(d)/'oidc.db',clock=lambda:now[0])
   principal=Principal('subject',frozenset({'reader'}),verified=True)
   store.put_session('sid',principal,200);store.bind_csrf('sid','secret')
   self.assertTrue(store.verify_csrf('sid','secret'))
   self.assertFalse(store.verify_csrf('sid','wrong'))
   now[0]=201
   self.assertFalse(store.verify_csrf('sid','secret'))
   store.delete_session('sid');self.assertFalse(store.verify_csrf('sid','secret'))
 def test_cross_session_rejection_and_restart(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'oidc.db';store=SQLiteOIDCStore(path,clock=lambda:100)
   principal=Principal('subject',frozenset({'reader'}),verified=True)
   for sid,token in [('a','token-a'),('b','token-b')]:
    store.put_session(sid,principal,200);store.bind_csrf(sid,token)
   other=SQLiteOIDCStore(path,clock=lambda:100)
   self.assertTrue(other.verify_csrf('a','token-a'))
   self.assertFalse(other.verify_csrf('b','token-a'))
   other.delete_session('a');self.assertFalse(store.verify_csrf('a','token-a'))
if __name__=='__main__':unittest.main()
