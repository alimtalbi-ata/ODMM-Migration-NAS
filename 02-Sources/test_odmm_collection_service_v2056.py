import unittest
from unittest.mock import patch
from odmm_collection_service_v2056 import collect_inventory, attach_collection_api, ServiceError
class TestCollectionService(unittest.TestCase):
 def test_token_provider_required(self):
  with self.assertRaises(ServiceError): collect_inventory('netapp_ontap','nas.example',token_provider=None,allow_hosts=['nas.example'])
 def test_allowlist(self):
  with self.assertRaises(ServiceError): collect_inventory('netapp_ontap','evil.example',token_provider=lambda *_:'secret',allow_hosts=['nas.example'])
 def test_no_secret_no_raw_payload(self):
  response={'vendor':'netapp_ontap','host':'nas.example','endpoint':'/api/cluster','provenance':'authenticated_https_get','response_sha256':'a'*64,'reported_keys':['name'],'raw_payload':{'private':'SECRET'},'status':'UNVERIFIED'}
  with patch('odmm_collection_service_v2056.collect',return_value=response):
   report=collect_inventory('netapp_ontap','nas.example',token_provider=lambda *_:'SECRET',allow_hosts=['nas.example'])
  self.assertNotIn('SECRET',str(report));self.assertNotIn('raw_payload',report);self.assertFalse(report['cutover_authorized'])
 def test_auth_required(self):
  with self.assertRaises(ServiceError): attach_collection_api(object(),authorize=None,token_provider=lambda *_:'x',allow_hosts=[])
 def test_route_auth(self):
  from fastapi import FastAPI
  from fastapi.testclient import TestClient
  app=FastAPI()
  attach_collection_api(app,authorize=lambda request:False,token_provider=lambda *_:'secret',allow_hosts=['nas.example'])
  self.assertEqual(TestClient(app).post('/api/v1/qualification/collect',json={'vendor':'netapp_ontap','host':'nas.example'}).status_code,403)
 def test_route_success(self):
  from fastapi import FastAPI
  from fastapi.testclient import TestClient
  app=FastAPI()
  attach_collection_api(app,authorize=lambda request:True,token_provider=lambda *_:'secret',allow_hosts=['nas.example'],collector=lambda *a,**k:{'status':'UNVERIFIED','cutover_authorized':False})
  r=TestClient(app).post('/api/v1/qualification/collect',json={'vendor':'netapp_ontap','host':'nas.example'})
  self.assertEqual(r.status_code,200);self.assertFalse(r.json()['cutover_authorized'])
 def test_route_extra_field(self):
  from fastapi import FastAPI
  from fastapi.testclient import TestClient
  app=FastAPI()
  attach_collection_api(app,authorize=lambda request:True,token_provider=lambda *_:'secret',allow_hosts=['nas.example'])
  self.assertEqual(TestClient(app).post('/api/v1/qualification/collect',json={'vendor':'netapp_ontap','host':'nas.example','token':'secret'}).status_code,422)
if __name__=='__main__':unittest.main()
