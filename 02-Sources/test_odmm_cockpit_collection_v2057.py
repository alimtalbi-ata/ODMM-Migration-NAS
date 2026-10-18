import unittest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_cockpit_collection_v2057 import PAGE, cockpit_csp, attach_collection_cockpit
class TestCockpit(unittest.TestCase):
 def test_ui_controls(self):
  for x in ['coll-start','coll-file','coll-host','CUTOVER INTERDIT','/api/v1/qualification/collect']:self.assertIn(x,PAGE)
 def test_safe_dom(self):self.assertIn('td.textContent=s',PAGE)
 def test_csp(self):
  self.assertIn("connect-src 'self'",cockpit_csp());self.assertIn("default-src 'none'",cockpit_csp())
 def test_denied(self):
  app=FastAPI();attach_collection_cockpit(app,authorize=lambda req:False)
  self.assertEqual(TestClient(app).get('/qualification/cockpit').status_code,403)
 def test_allowed(self):
  app=FastAPI();attach_collection_cockpit(app,authorize=lambda req:True)
  r=TestClient(app).get('/qualification/cockpit')
  self.assertEqual(r.status_code,200);self.assertEqual(r.headers['cache-control'],'no-store')
 def test_requires_auth(self):
  with self.assertRaises(ValueError):attach_collection_cockpit(FastAPI(),authorize=None)
if __name__=='__main__':unittest.main()
