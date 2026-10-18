import json,pytest
from odmm_oidc_transport_v2069 import TrustedOIDCTransport
from odmm_oidc_pkce_v2068 import OIDCVerificationError
ISS='https://idp.example/realm'
def make(*,discovery=None,jwks=None):
    calls=[]
    def get(url):
        calls.append(url)
        if url.endswith('openid-configuration'):
            return json.dumps(discovery or {'issuer':ISS,'authorization_endpoint':ISS+'/auth','token_endpoint':ISS+'/token','jwks_uri':ISS+'/keys'}).encode()
        return json.dumps(jwks or {'keys':[]}).encode()
    def post(url,body):
        calls.append((url,body));return b'{"id_token":"signed-token"}'
    return TrustedOIDCTransport(issuer=ISS,client_id='odmm',http_get=get,http_post=post,clock=lambda:1000),calls

def test_discovery_cache_and_jwks():
    t,c=make();assert t.discovery()['issuer']==ISS;assert t.discovery()['issuer']==ISS
    assert t.jwks()=={'keys':[]};assert t.jwks()=={'keys':[]};assert len(c)==2

def test_exchange_pkce():
    t,c=make();assert t.exchange(code='abc',verifier='secret',redirect_uri='https://odmm.example/callback')=='signed-token'
    assert c[-1][1]['code_verifier']=='secret'

def test_reject_untrusted_jwks():
    t,_=make(discovery={'issuer':ISS,'authorization_endpoint':ISS+'/auth','token_endpoint':ISS+'/token','jwks_uri':'https://evil.example/keys'})
    with pytest.raises(OIDCVerificationError,match='UNTRUSTED_ENDPOINT'):t.discovery()

def test_reject_issuer_mismatch():
    t,_=make(discovery={'issuer':'https://evil.example'})
    with pytest.raises(OIDCVerificationError,match='ISSUER_MISMATCH'):t.discovery()

def test_reject_insecure_or_cross_origin_token_endpoint():
    t,_=make(discovery={'issuer':ISS,'authorization_endpoint':ISS+'/auth','token_endpoint':'http://idp.example/token','jwks_uri':ISS+'/keys'})
    with pytest.raises(OIDCVerificationError):t.discovery()

def test_reject_invalid_callback():
    t,_=make()
    with pytest.raises(OIDCVerificationError):t.exchange(code='',verifier='secret',redirect_uri='https://odmm.example/callback')

def test_reject_huge_response():
    t,_=make();t.get=lambda url:b'x'*70000
    with pytest.raises(OIDCVerificationError):t.discovery()
