import tempfile,unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_session_registry_v2062 import SessionRegistry
from odmm_session_routes_v2065 import attach_session_routes
from odmm_secure_integration_v2059 import csrf_for_session

KEY=b'k'*32; SECRET=b'c'*32; ORIGIN='https://odmm.example'
class RoutesTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.now=[1000.0];self.registry=SessionRegistry(Path(self.tmp.name)/'db',key=KEY,clock=lambda:self.now[0]);self.token=self.registry.issue('alice','operator',ttl=300)
  self.app=FastAPI();attach_session_routes(self.app,registry=self.registry,csrf_secret=SECRET,expected_origin=ORIGIN);self.client=TestClient(self.app)
 def post(self,path,token=None,origin=ORIGIN,csrf=None):
  token=self.token if token is None else token;csrf=csrf_for_session(token,SECRET) if csrf is None else csrf
  return self.client.post('/api/v1/session/'+path,headers={'Origin':origin,'X-ODMM-CSRF':csrf},cookies={'odmm_session':token,'odmm_csrf':csrf})
 def test_rotate_revokes_old(self):
  r=self.post('rotate');self.assertEqual(r.status_code,200);self.assertIsNone(self.registry.resolve(self.token));new=r.cookies.get('odmm_session');self.assertIsNotNone(self.registry.resolve(new));self.assertEqual(self.post('rotate').status_code,401)
 def test_logout(self):
  r=self.post('logout');self.assertEqual(r.status_code,200);self.assertIsNone(self.registry.resolve(self.token));self.assertEqual(self.post('logout').status_code,401)
 def test_cross_session_csrf(self):
  other=self.registry.issue('bob','operator');self.assertEqual(self.post('rotate',csrf=csrf_for_session(other,SECRET)).status_code,403)
 def test_bad_origin(self):
  for origin in ('http://odmm.example','https://odmm.example/evil','https://evil.example','https://odmm.example?x=1',''):
   self.assertEqual(self.post('rotate',origin=origin).status_code,403)
 def test_expired(self):
  self.now[0]=1301;self.assertEqual(self.post('rotate').status_code,401)
 def test_concurrent_rotate_one_winner(self):
  with ThreadPoolExecutor(max_workers=10) as pool:codes=list(pool.map(lambda _:self.post('rotate').status_code,range(20)))
  self.assertEqual(codes.count(200),1);self.assertEqual(codes.count(401),19)
 def test_duplicate_route(self):
  with self.assertRaises(ValueError):attach_session_routes(self.app,registry=self.registry,csrf_secret=SECRET,expected_origin=ORIGIN)
 def test_secure_cookies(self):
  r=self.post('rotate');cookies=r.headers.get_list('set-cookie');self.assertEqual(len(cookies),2);self.assertTrue(all('secure' in c.lower() and 'samesite=strict' in c.lower() for c in cookies));self.assertIn('httponly',cookies[0].lower());self.assertNotIn('httponly',cookies[1].lower())
if __name__=='__main__':unittest.main()
