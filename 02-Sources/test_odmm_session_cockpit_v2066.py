import unittest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_session_cockpit_v2066 import PAGE,cockpit_csp,attach_session_cockpit

class CockpitTests(unittest.TestCase):
 def test_controls(self):
  for part in ('session-rotate','session-logout','session-feedback','/api/v1/session/','X-ODMM-CSRF','credentials:\'same-origin\'','CUTOVER'):
   self.assertIn(part,PAGE)
 def test_csp(self):
  c=cockpit_csp();self.assertIn("connect-src 'self'",c);self.assertIn('sha256-',c);self.assertNotIn('unsafe-inline',c)
 def test_denied(self):
  app=FastAPI();attach_session_cockpit(app,authorize=lambda _:False)
  with TestClient(app) as client:self.assertEqual(client.get('/qualification/cockpit').status_code,403)
 def test_allowed(self):
  app=FastAPI();attach_session_cockpit(app,authorize=lambda _:True)
  with TestClient(app) as client:
   r=client.get('/qualification/cockpit');self.assertEqual(r.status_code,200);self.assertIn('no-store',r.headers['cache-control']);self.assertIn('session-rotate',r.text)
 def test_duplicate(self):
  app=FastAPI();attach_session_cockpit(app,authorize=lambda _:True)
  with self.assertRaises(ValueError):attach_session_cockpit(app,authorize=lambda _:True)
 def test_no_untrusted_html(self):
  self.assertNotIn('innerHTML',PAGE)
if __name__=='__main__':unittest.main()
