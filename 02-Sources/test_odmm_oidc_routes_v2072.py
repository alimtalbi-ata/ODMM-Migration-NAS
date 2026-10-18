import secrets
from urllib.parse import urlsplit,parse_qs
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_oidc_routes_v2072 import attach_oidc_routes
from odmm_oidc_transactions_v2071 import SQLitePKCETransactions
from odmm_session_registry_v2062 import SessionRegistry

ISSUER='https://idp.example'; CALLBACK='https://odmm.example/auth/oidc/callback'
class MockTransport:
    issuer=ISSUER;client_id='odmm'
    def discovery(self):return {'authorization_endpoint':ISSUER+'/authorize'}
    def complete(self,*,transaction,code):
        import time
        if code!='valid':raise ValueError('INVALID_CODE')
        now=time.time()
        return {'iss':ISSUER,'aud':'odmm','nonce':transaction['nonce'],'sub':'test-user','iat':now,'exp':now+600,'groups':['odmm-operator']}

def setup(tmp_path):
    app=FastAPI(); sessions=SessionRegistry(tmp_path/'sessions.db',key=b's'*32)
    transactions=SQLitePKCETransactions(tmp_path/'pkce.db',key=b'p'*32)
    attach_oidc_routes(app,transport=MockTransport(),transactions=transactions,sessions=sessions,csrf_secret=b'c'*32,redirect_uri=CALLBACK)
    return TestClient(app,base_url='https://odmm.example'),sessions

def test_login_callback_and_replay(tmp_path):
    client,sessions=setup(tmp_path)
    start=client.get('/auth/oidc/login',follow_redirects=False)
    assert start.status_code==303
    query=parse_qs(urlsplit(start.headers['location']).query)
    assert query['code_challenge_method']==['S256']
    assert 'Secure' in start.headers['set-cookie'] and 'httponly' in start.headers['set-cookie'].lower()
    state=query['state'][0]
    callback=client.get('/auth/oidc/callback',params={'state':state,'code':'valid'})
    assert callback.status_code==200
    assert sessions.resolve(client.cookies.get('odmm_session'))['role']=='operator'
    assert client.get('/auth/oidc/callback',params={'state':state,'code':'valid'}).status_code==401

def test_browser_binding_and_error(tmp_path):
    client,_=setup(tmp_path)
    start=client.get('/auth/oidc/login',follow_redirects=False)
    state=parse_qs(urlsplit(start.headers['location']).query)['state'][0]
    other=TestClient(client.app,base_url='https://odmm.example')
    assert other.get('/auth/oidc/callback',params={'state':state,'code':'valid'}).status_code==401
    assert client.get('/auth/oidc/callback',params={'state':state,'code':'valid'}).status_code==200
    assert client.get('/auth/oidc/callback',params={'error':'access_denied'}).status_code==401

def test_insecure_scheme_and_duplicate_routes(tmp_path):
    client,_=setup(tmp_path)
    plain=TestClient(client.app,base_url='http://odmm.example')
    assert plain.get('/auth/oidc/login').status_code==403
    assert plain.get('/auth/oidc/callback').status_code==403
