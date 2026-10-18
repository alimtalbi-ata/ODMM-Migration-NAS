import unittest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_capability_cockpit_v2051 import PAGE,cockpit_csp,attach_capability_cockpit
class TestV2051(unittest.TestCase):
 def test_ui(self):
  for s in ('cap-source-file','cap-target-file','cap-pair','cap-rows','UNVERIFIED','Cutover interdit'):self.assertIn(s,PAGE)
 def test_no_remote_io(self):
  for s in ('fetch(', 'XMLHttpRequest','sendBeacon('):self.assertNotIn(s,PAGE)
 def test_csp(self):self.assertEqual(cockpit_csp().count("'sha256-"),5)
 def test_auth_required(self):
  with self.assertRaises(ValueError):attach_capability_cockpit(FastAPI(),authorize=None)
 def test_auth_denied(self):
  app=FastAPI();attach_capability_cockpit(app,authorize=lambda req:False)
  self.assertEqual(TestClient(app).get('/qualification/cockpit').status_code,403)
 def test_auth_allowed(self):
  app=FastAPI();attach_capability_cockpit(app,authorize=lambda req:True)
  r=TestClient(app).get('/qualification/cockpit');self.assertEqual(r.status_code,200);self.assertIn('Content-Security-Policy',r.headers)
 def test_no_cutover(self):self.assertNotIn('cutover_authorized=true',PAGE)
if __name__=='__main__':unittest.main()
