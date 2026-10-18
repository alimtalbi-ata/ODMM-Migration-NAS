import sqlite3
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
from odmm_oidc_browser import BrowserOIDCConfig,create_browser_app,_b64
from odmm_oidc_verifier import OIDCVerifier
from registry import Registry
import json,time

class BrowserFlowTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); root=Path(self.tmp.name)
  self.db=root/'registry.db'; self.grants=root/'grants.db'
  with Registry(str(self.db)) as r:
   self.job=r.create_job('nas1','nas2')
  with sqlite3.connect(self.grants) as db:
   db.execute('CREATE TABLE job_grants(subject TEXT,job_id TEXT)')
   db.execute('INSERT INTO job_grants VALUES (?,?)',('alice',self.job))
  self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  public=self.key.public_key().public_numbers()
  self.verifier=OIDCVerifier(issuer='https://id.example',audience='odmm',jwks={'keys':[{'kid':'one','kty':'RSA','n':_b64(public.n.to_bytes(256,'big')),'e':_b64(public.e.to_bytes(3,'big'))}]})
  self.config=BrowserOIDCConfig('https://id.example/authorize','https://id.example/token','odmm','https://odmm.example/auth/callback','https://odmm.example')
  self.nonce=None
  def exchange(code,pkce,redirect):
   self.assertEqual(code,'valid-code'); self.assertGreater(len(pkce),40)
   return {'id_token':self.token(nonce=self.nonce),'access_token':self.token()}
  self.app=create_browser_app(registry_path=str(self.db),grants_path=str(self.grants),verifier=self.verifier,config=self.config,exchange_code=exchange)
  self.client=TestClient(self.app,base_url='https://odmm.example',follow_redirects=False)
 def tearDown(self): self.client.close();self.tmp.cleanup()
 def token(self,nonce=None):
  payload={'iss':'https://id.example','aud':'odmm','sub':'alice','roles':['viewer'],'exp':int(time.time())+300}
  if nonce is not None:payload['nonce']=nonce
  header=_b64(json.dumps({'alg':'RS256','kid':'one'}).encode()); body=_b64(json.dumps(payload).encode())
  signature=self.key.sign((header+'.'+body).encode(),padding.PKCS1v15(),hashes.SHA256())
  return header+'.'+body+'.'+_b64(signature)
 def begin(self):
  response=self.client.get('/auth/login');self.assertEqual(response.status_code,303)
  params=parse_qs(urlsplit(response.headers['location']).query)
  self.nonce=params['nonce'][0]
  self.assertEqual(params['code_challenge_method'],['S256'])
  return params['state'][0]
 def test_no_session_denied(self): self.assertEqual(self.client.get('/api/v1/operations/jobs').status_code,403)
 def test_login_and_scope(self):
  state=self.begin();response=self.client.get('/auth/callback',params={'state':state,'code':'valid-code'})
  self.assertEqual(response.status_code,303)
  self.assertIn('Secure',response.headers['set-cookie']);self.assertIn('HttpOnly',response.headers['set-cookie'])
  self.assertEqual(len(self.client.get('/api/v1/operations/jobs').json()['items']),1)
  self.assertEqual(self.client.get('/api/v1/operations/jobs/ungranted/operations').status_code,404)
  self.assertEqual(self.client.get('/operations').status_code,200)
 def test_state_replay_rejected(self):
  state=self.begin();self.assertEqual(self.client.get('/auth/callback',params={'state':state,'code':'valid-code'}).status_code,303)
  self.assertEqual(self.client.get('/auth/callback',params={'state':state,'code':'valid-code'}).status_code,403)
 def test_bad_state_rejected(self): self.assertEqual(self.client.get('/auth/callback',params={'state':'x','code':'x'}).status_code,403)
 def test_logout_origin_guard(self):
  self.assertEqual(self.client.post('/auth/logout').status_code,403)
  self.assertEqual(self.client.post('/auth/logout',headers={'origin':'https://odmm.example'}).status_code,303)
 def test_no_legacy_routes(self):
  self.assertEqual(self.client.get('/docs').status_code,404)
  self.assertEqual(self.client.get('/openapi.json').status_code,404)
 def test_bad_config(self):
  with self.assertRaises(ValueError): BrowserOIDCConfig('http://id.example','https://id.example/token','id','https://odmm.example/auth/callback','https://odmm.example').validate()

if __name__=='__main__':unittest.main()
