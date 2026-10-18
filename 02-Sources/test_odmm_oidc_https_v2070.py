import json,pytest,httpx
from odmm_oidc_https_v2070 import make_trusted_oidc
from odmm_oidc_pkce_v2068 import OIDCVerificationError
ISS='https://idp.example/realm'
def setup(mode='ok'):
    seen=[]
    def handler(request):
        seen.append((request.method,str(request.url)))
        if mode=='redirect':return httpx.Response(302,headers={'location':'https://evil.example/'})
        if mode=='wrong_type':return httpx.Response(200,content=b'{}',headers={'content-type':'text/html'})
        if mode=='large':return httpx.Response(200,content=b'x'*140000,headers={'content-type':'application/json'})
        if request.url.path.endswith('openid-configuration'):
            return httpx.Response(200,json={'issuer':ISS,'authorization_endpoint':ISS+'/auth','token_endpoint':ISS+'/token','jwks_uri':ISS+'/jwks'})
        if request.url.path.endswith('jwks'):return httpx.Response(200,json={'keys':[]})
        return httpx.Response(200,json={'id_token':'signed-token'})
    client=httpx.Client(transport=httpx.MockTransport(handler),follow_redirects=False)
    transport,network=make_trusted_oidc(issuer=ISS,client_id='odmm',client=client)
    return transport,network,seen

def test_https_discovery_jwks_exchange():
    t,h,seen=setup();assert t.discovery()['issuer']==ISS
    assert t.jwks()=={'keys':[]}
    assert t.exchange(code='code',verifier='verifier',redirect_uri='https://portal.example/callback')=='signed-token'
    assert [x[0] for x in seen]==['GET','GET','POST']
@pytest.mark.parametrize('mode',('redirect','wrong_type','large'))
def test_fail_closed_response(mode):
    t,_,_=setup(mode)
    with pytest.raises(OIDCVerificationError):t.discovery()
def test_reject_cross_origin():
    t,h,_=setup()
    with pytest.raises(OIDCVerificationError,match='UNTRUSTED_ENDPOINT'):h.get('https://evil.example/config')
def test_reject_http():
    t,h,_=setup()
    with pytest.raises(OIDCVerificationError):h.get('http://idp.example/realm/config')
def test_invalid_timeout():
    with pytest.raises(ValueError):make_trusted_oidc(issuer=ISS,client_id='odmm',timeout=0)
