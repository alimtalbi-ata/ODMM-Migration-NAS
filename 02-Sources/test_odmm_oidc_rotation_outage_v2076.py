"""JWKS rotation and transport outage tests. Auteur: Abdelhalim Talbi."""
import json
import httpx
import pytest
from odmm_oidc_transport_v2069 import TrustedOIDCTransport
from odmm_oidc_https_v2070 import StrictOIDCHTTP
from odmm_oidc_pkce_v2068 import OIDCVerificationError

ISSUER='https://idp.example'
def test_jwks_refresh_returns_rotated_key():
    state={'kid':'old','count':0}
    def get(url):
        if url.endswith('openid-configuration'):
            return json.dumps({'issuer':ISSUER,'authorization_endpoint':ISSUER+'/authorize','token_endpoint':ISSUER+'/token','jwks_uri':ISSUER+'/jwks'}).encode()
        state['count']+=1
        return json.dumps({'keys':[{'kid':state['kid'],'kty':'RSA'}]}).encode()
    t=TrustedOIDCTransport(issuer=ISSUER,client_id='odmm',http_get=get,http_post=lambda u,b:b'{}')
    assert t.jwks()['keys'][0]['kid']=='old'
    state['kid']='new'
    assert t.jwks()['keys'][0]['kid']=='old'
    assert t.jwks(refresh=True)['keys'][0]['kid']=='new'
    assert state['count']==2

def test_network_outage_does_not_fallback_to_insecure_transport():
    def fail(request):raise httpx.ConnectError('offline',request=request)
    client=httpx.Client(transport=httpx.MockTransport(fail),trust_env=False)
    strict=StrictOIDCHTTP(issuer=ISSUER,client=client)
    with pytest.raises(httpx.ConnectError):strict.get(ISSUER+'/jwks')
    with pytest.raises(OIDCVerificationError,match='UNTRUSTED_ENDPOINT'):strict.get('https://evil.example/jwks')
    client.close()
