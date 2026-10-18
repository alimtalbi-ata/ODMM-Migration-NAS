import unittest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_qualification_portal_v2048 import PAGE,csp,attach_qualification_portal
class TestQualificationPortal(unittest.TestCase):
 def test_denies_without_authorizer(self):
  with self.assertRaises(ValueError):attach_qualification_portal(FastAPI(),authorize=None)
 def test_denies_unauthorized(self):
  app=FastAPI();attach_qualification_portal(app,authorize=lambda request:False)
  self.assertEqual(TestClient(app).get('/qualification').status_code,403)
 def test_authenticated(self):
  app=FastAPI();attach_qualification_portal(app,authorize=lambda request:True)
  r=TestClient(app).get('/qualification');self.assertEqual(r.status_code,200);self.assertIn('no-store',r.headers['cache-control'])
 def test_strict_csp(self):self.assertIn("default-src 'none'",csp())
 def test_no_network_calls(self):self.assertNotIn('fetch(',PAGE)
 def test_no_inner_html(self):self.assertNotIn('innerHTML',PAGE)
 def test_cutover_blocked(self):self.assertIn('Cutover : INTERDIT',PAGE)
 def test_vendor_list(self):
  for v in ('netapp_ontap','dell_powerscale','truenas_scale'):self.assertIn(v,PAGE)
if __name__=='__main__':unittest.main()
