import unittest
from odmm_unified_cockpit_v2050 import PAGE,cockpit_csp,attach_unified_cockpit
class TestCockpit(unittest.TestCase):
 def test_sections(self):
  for s in ('unified-cockpit','src-device','dst-device','acl-status','unified-file','BLOCKED','NO_EVIDENCE'):self.assertIn(s,PAGE)
 def test_csp(self):self.assertEqual(cockpit_csp().count("'sha256-"),4)
 def test_auth_required(self):
  with self.assertRaises(ValueError):attach_unified_cockpit(None,authorize=None)
 def test_auth_denied(self):
  from fastapi import FastAPI
  from fastapi.testclient import TestClient
  app=FastAPI();attach_unified_cockpit(app,authorize=lambda r:False)
  self.assertEqual(TestClient(app).get('/qualification/cockpit').status_code,403)
 def test_auth_allowed(self):
  from fastapi import FastAPI
  from fastapi.testclient import TestClient
  app=FastAPI();attach_unified_cockpit(app,authorize=lambda r:True)
  r=TestClient(app).get('/qualification/cockpit');self.assertEqual(r.status_code,200);self.assertIn('Content-Security-Policy',r.headers)
 def test_no_remote_action(self):
  self.assertNotIn('fetch(',PAGE);self.assertNotIn('XMLHttpRequest',PAGE)
if __name__=='__main__':unittest.main()
