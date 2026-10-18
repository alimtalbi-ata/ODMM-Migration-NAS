import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_collection_gate_v2061 import TransactionalSecurityGate
from odmm_session_registry_v2062 import SessionRegistry
from odmm_session_binding_v2063 import attach_session_qualification
from odmm_secure_integration_v2059 import csrf_for_session

ORIGIN='https://odmm.example'; KEY=b'k'*32; CSRF=b'c'*32

class BindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.now=[1000.0]
        self.registry=SessionRegistry(Path(self.tmp.name)/'sessions.sqlite',key=KEY,clock=lambda:self.now[0])
        self.token=self.registry.issue('alice','operator',ttl=100)
        self.app=FastAPI(); self.calls=[]
        self.gate=TransactionalSecurityGate(str(Path(self.tmp.name)/'gate.sqlite'),max_requests=100)
        def collector(vendor,host,**kwargs):
            self.calls.append((vendor,host))
            return {'status':'UNVERIFIED','cutover_authorized':False}
        attach_session_qualification(self.app,registry=self.registry,gate=self.gate,csrf_secret=CSRF,
          expected_origin=ORIGIN,token_provider=lambda *a:'dummy',allow_hosts={'nas.example'},collector=collector)
        self.client=TestClient(self.app)
    def request(self, token=None, csrf=None):
        token=self.token if token is None else token
        csrf=(csrf_for_session(token,CSRF) if len(token)>=16 else '') if csrf is None else csrf
        return self.client.post('/api/v1/qualification/collect-hardened',
          headers={'Origin':ORIGIN,'X-ODMM-CSRF':csrf},
          cookies={'odmm_session':token,'odmm_csrf':csrf},json={'vendor':'netapp_ontap','host':'nas.example'})
    def test_valid_session(self):self.assertEqual(self.request().status_code,200)
    def test_missing_session(self):self.assertEqual(self.request(token='').status_code,401)
    def test_expired_session(self):
        self.now[0]=1101.0
        self.assertEqual(self.request().status_code,401)
        self.assertEqual(self.client.get('/qualification/cockpit',cookies={'odmm_session':self.token}).status_code,403)
    def test_revoked_session(self):
        self.assertTrue(self.registry.revoke(self.token))
        self.assertEqual(self.request().status_code,401)
    def test_viewer_denied_collection(self):
        token=self.registry.issue('bob','viewer')
        self.assertEqual(self.request(token=token).status_code,403)
        self.assertEqual(self.client.get('/qualification/cockpit',cookies={'odmm_session':token}).status_code,200)
    def test_cross_session_csrf_denied(self):
        other=self.registry.issue('bob','operator')
        self.assertEqual(self.request(csrf=csrf_for_session(other,CSRF)).status_code,403)
    def test_no_ui_session(self):self.assertEqual(self.client.get('/qualification/cockpit').status_code,403)
    def test_concurrent_revocation(self):
        self.registry.revoke(self.token)
        with ThreadPoolExecutor(max_workers=8) as pool:
            codes=list(pool.map(lambda _:self.request().status_code,range(12)))
        self.assertEqual(set(codes),{401})
        self.assertFalse(self.calls)

if __name__=='__main__':unittest.main()
