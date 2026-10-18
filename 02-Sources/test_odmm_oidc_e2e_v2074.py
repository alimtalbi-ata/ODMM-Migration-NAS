"""End-to-end OIDC with cryptographically signed local simulated provider.
Auteur: Abdelhalim Talbi. No production IdP is contacted.
"""
import base64, hashlib, json, time
from urllib.parse import urlsplit, parse_qs
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_oidc_pkce_v2068 import _b64
from odmm_oidc_https_v2070 import make_trusted_oidc
from odmm_oidc_transactions_v2071 import SQLitePKCETransactions
from odmm_oidc_routes_v2073 import attach_oidc_routes
from odmm_session_registry_v2062 import SessionRegistry

ISSUER='https://idp.local.test'; CALLBACK='https://odmm.local.test/auth/oidc/callback'

class LocalProvider:
    def __init__(self):
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        pub=self.key.public_key().public_numbers()
        self.jwks={'keys':[{'kty':'RSA','kid':'local-key','use':'sig','alg':'RS256',
            'n':_b64(pub.n.to_bytes((pub.n.bit_length()+7)//8,'big')),
            'e':_b64(pub.e.to_bytes((pub.e.bit_length()+7)//8,'big'))}]}
        self.requests=[];self.nonce=None;self.fail=False;self.rotate_key=False
    def handle(self, request):
        self.requests.append((request.method,str(request.url)))
        if self.fail:return httpx.Response(503,json={'error':'temporarily_unavailable'})
        path=request.url.path
        if path=='/.well-known/openid-configuration':
            return httpx.Response(200,json={'issuer':ISSUER,'authorization_endpoint':ISSUER+'/authorize','token_endpoint':ISSUER+'/token','jwks_uri':ISSUER+'/jwks'})
        if path=='/jwks':return httpx.Response(200,json=self.jwks)
        if path=='/token':
            from urllib.parse import parse_qs
            params=parse_qs(request.content.decode())
            if params.get('grant_type')!=['authorization_code'] or params.get('redirect_uri')!=[CALLBACK] or not params.get('code_verifier'):
                return httpx.Response(400,json={'error':'invalid_grant'})
            now=time.time();claims={'iss':ISSUER,'aud':'odmm','sub':'local-user','nonce':self.nonce,'iat':now,'exp':now+300,'groups':['odmm-operator']}
            body=_b64(json.dumps({'alg':'RS256','kid':'local-key'}).encode())+'.'+_b64(json.dumps(claims).encode())
            token=body+'.'+_b64(self.key.sign(body.encode(),padding.PKCS1v15(),hashes.SHA256()))
            return httpx.Response(200,json={'id_token':token,'token_type':'Bearer'})
        return httpx.Response(404,json={'error':'not_found'})

def build(tmp_path, provider):
    http=httpx.Client(transport=httpx.MockTransport(provider.handle),follow_redirects=False,trust_env=False)
    transport,adapter=make_trusted_oidc(issuer=ISSUER,client_id='odmm',client=http)
    sessions=SessionRegistry(tmp_path/'sessions.sqlite',key=b's'*32)
    tx=SQLitePKCETransactions(tmp_path/'pkce.sqlite',key=b'p'*32)
    app=FastAPI()
    attach_oidc_routes(app,transport=transport,transactions=tx,sessions=sessions,csrf_secret=b'c'*32,redirect_uri=CALLBACK)
    return TestClient(app,base_url='https://odmm.local.test'),sessions,http

def begin(client,provider):
    login=client.get('/auth/oidc/login',follow_redirects=False)
    assert login.status_code==303
    params=parse_qs(urlsplit(login.headers['location']).query)
    assert params['code_challenge_method']==['S256']
    provider.nonce=params['nonce'][0]
    return params['state'][0]

def test_full_signed_oidc_flow_and_replay(tmp_path):
    provider=LocalProvider();client,sessions,http=build(tmp_path,provider)
    try:
        state=begin(client,provider)
        response=client.get('/auth/oidc/callback',params={'state':state,'code':'local-code'})
        assert response.status_code==200,response.text
        assert sessions.resolve(client.cookies.get('odmm_session'))['role']=='operator'
        assert client.cookies.get('odmm_csrf')
        assert not client.cookies.get('odmm_oidc_binding')
        assert client.get('/auth/oidc/callback',params={'state':state,'code':'local-code'}).status_code==401
        assert sum(path.endswith('/token') for _,path in provider.requests)==1
    finally:http.close()

def test_cross_browser_and_restart(tmp_path):
    provider=LocalProvider();client,sessions,http=build(tmp_path,provider)
    try:
        state=begin(client,provider)
        stranger,_,otherhttp=build(tmp_path,provider)
        try:
            assert stranger.get('/auth/oidc/callback',params={'state':state,'code':'x'}).status_code==401
            restarted,_,thirdhttp=build(tmp_path,provider)
            try:
                restarted.cookies.set('odmm_oidc_binding',client.cookies.get('odmm_oidc_binding'))
                assert restarted.get('/auth/oidc/callback',params={'state':state,'code':'x'}).status_code==200
            finally:thirdhttp.close()
        finally:otherhttp.close()
    finally:http.close()

def test_provider_unavailable_and_fail_closed(tmp_path):
    provider=LocalProvider();client,_,http=build(tmp_path,provider)
    try:
        state=begin(client,provider)
        provider.fail=True
        response=client.get('/auth/oidc/callback',params={'state':state,'code':'x'})
        assert response.status_code in (401,503)
        assert not client.cookies.get('odmm_session')
        provider.fail=False
        assert client.get('/auth/oidc/callback',params={'state':state,'code':'x'}).status_code==401
    finally:http.close()

def test_https_only_and_origin_pinning(tmp_path):
    provider=LocalProvider();client,_,http=build(tmp_path,provider)
    try:
        assert client.get('/auth/oidc/login',follow_redirects=False).status_code==303
        insecure=TestClient(client.app,base_url='http://odmm.local.test')
        assert insecure.get('/auth/oidc/login').status_code==403
        assert all(urlsplit(url).hostname=='idp.local.test' for _,url in provider.requests)
    finally:http.close()
