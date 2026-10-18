"""Provider outages, callback replay and restart recovery; no real IdP involved."""
import httpx
from urllib.parse import urlsplit,parse_qs
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_oidc_routes_v2073 import attach_oidc_routes
from odmm_oidc_transactions_v2071 import SQLitePKCETransactions
from odmm_session_registry_v2062 import SessionRegistry

class Provider:
    issuer='https://idp.example';client_id='odmm'
    def __init__(self):self.down_login=False;self.down_callback=False
    def discovery(self):
        if self.down_login:raise httpx.ConnectError('secret upstream hostname')
        return {'authorization_endpoint':self.issuer+'/authorize'}
    def complete(self,*,transaction,code):
        if self.down_callback:raise httpx.ReadTimeout('secret upstream address')
        import time
        now=time.time()
        return {'iss':self.issuer,'aud':self.client_id,'nonce':transaction['nonce'],'sub':'test-user','iat':now,'exp':now+600,'groups':['odmm-operator']}

def create(tmp_path,provider):
    app=FastAPI()
    sessions=SessionRegistry(tmp_path/'sessions.db',key=b's'*32)
    tx=SQLitePKCETransactions(tmp_path/'pkce.db',key=b'p'*32)
    attach_oidc_routes(app,transport=provider,transactions=tx,sessions=sessions,csrf_secret=b'c'*32,redirect_uri='https://odmm.example/auth/oidc/callback')
    return TestClient(app,base_url='https://odmm.example'),sessions

def test_login_provider_outage_and_recovery(tmp_path):
    provider=Provider();client,_=create(tmp_path,provider)
    provider.down_login=True
    r=client.get('/auth/oidc/login',follow_redirects=False)
    assert r.status_code==503 and r.headers['retry-after']=='30' and 'secret' not in r.text
    provider.down_login=False
    assert client.get('/auth/oidc/login',follow_redirects=False).status_code==303

def test_callback_outage_consumes_state_and_no_session(tmp_path):
    provider=Provider();client,sessions=create(tmp_path,provider)
    start=client.get('/auth/oidc/login',follow_redirects=False)
    state=parse_qs(urlsplit(start.headers['location']).query)['state'][0]
    provider.down_callback=True
    r=client.get('/auth/oidc/callback',params={'state':state,'code':'valid'})
    assert r.status_code==503 and 'secret' not in r.text
    assert not client.cookies.get('odmm_session')
    provider.down_callback=False
    assert client.get('/auth/oidc/callback',params={'state':state,'code':'valid'}).status_code==401

def test_restart_between_login_callback(tmp_path):
    provider=Provider();client,_=create(tmp_path,provider)
    start=client.get('/auth/oidc/login',follow_redirects=False)
    state=parse_qs(urlsplit(start.headers['location']).query)['state'][0]
    restarted,sessions=create(tmp_path,provider)
    restarted.cookies.set('odmm_oidc_binding',client.cookies.get('odmm_oidc_binding'))
    r=restarted.get('/auth/oidc/callback',params={'state':state,'code':'valid'})
    assert r.status_code==200
    assert sessions.resolve(restarted.cookies.get('odmm_session'))['role']=='operator'
