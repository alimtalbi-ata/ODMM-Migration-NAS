import unittest
import tempfile
import os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_deployment_v2060 import attach_qualification
from odmm_collection_security_v2058 import SecurityGate
from odmm_secure_integration_v2059 import csrf_for_session

SESSION='session-123456789';SECRET=b's'*32;ORIGIN='https://odmm.example'
class DeploymentTests(unittest.TestCase):
 def setUp(self):
  self.app=FastAPI();self.calls=[]
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  def collector(vendor,host,**kwargs):
   self.calls.append((vendor,host));return {'schema':'odmm.collection.v2056','vendor':vendor,'host':host,'status':'UNVERIFIED','cutover_authorized':False}
  self.args=dict(authorize=lambda r:True,gate=SecurityGate(os.path.join(self.tmp.name,'audit.sqlite'),max_requests=2),identity_provider=lambda r:('alice','operator'),session_provider=lambda r:SESSION,csrf_secret=SECRET,expected_origin=ORIGIN,token_provider=lambda *args:'fake',allow_hosts={'nas.example'},collector=collector)
  attach_qualification(self.app,**self.args);self.client=TestClient(self.app)
 def headers(self):return {'Origin':ORIGIN,'Content-Type':'application/json','X-ODMM-CSRF':csrf_for_session(SESSION,SECRET)}
 def request(self,headers=None,cookies=True,payload=None):
  return self.client.post('/api/v1/qualification/collect-hardened',headers=headers or self.headers(),cookies={'odmm_csrf':csrf_for_session(SESSION,SECRET)} if cookies else {},json=payload or {'vendor':'netapp_ontap','host':'nas.example'})
 def test_cockpit_http(self):
  r=self.client.get('/qualification/cockpit');self.assertEqual(r.status_code,200);self.assertIn('/collect-hardened',r.text);self.assertNotIn("fetch('/api/v1/qualification/collect-secure'",r.text)
 def test_cockpit_csp(self):self.assertIn('script-src',self.client.get('/qualification/cockpit').headers['content-security-policy'])
 def test_success(self):
  r=self.request();self.assertEqual(r.status_code,200);self.assertEqual(len(self.calls),1);self.assertFalse(r.json()['cutover_authorized'])
 def test_no_cookie(self):self.assertEqual(self.request(cookies=False).status_code,403)
 def test_wrong_origin(self):
  h=self.headers();h['Origin']='https://evil.example';self.assertEqual(self.request(headers=h).status_code,403)
 def test_bad_csrf(self):
  h=self.headers();h['X-ODMM-CSRF']='wrong';self.assertEqual(self.request(headers=h).status_code,403)
 def test_invalid_payload(self):self.assertEqual(self.request(payload={'vendor':'netapp_ontap','host':'nas.example','token':'leak'}).status_code,422)
 def test_rate_limit(self):
  self.assertEqual(self.request().status_code,200);self.assertEqual(self.request().status_code,200);self.assertEqual(self.request().status_code,429)
 def test_legacy_conflict(self):
  app=FastAPI();app.add_api_route('/api/v1/qualification/collect-secure',lambda:None)
  with self.assertRaises(ValueError):attach_qualification(app,**self.args)
 def test_unauthorized_ui(self):
  app=FastAPI();args={**self.args,'authorize':lambda r:False};attach_qualification(app,**args)
  self.assertEqual(TestClient(app).get('/qualification/cockpit').status_code,403)
if __name__=='__main__':unittest.main()
