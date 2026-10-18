import json
import pytest
from odmm_oidc_jwks_v2108 import CachedJWKSProvider,JWKSUnavailable
from test_odmm_oidc_boundary_v2107 import keys,signed
from odmm_oidc_boundary_v2107 import OIDCVerifier

class Response:
    status=200
    def __init__(self, url, data):self.url=url;self.data=data
    def __enter__(self):return self
    def __exit__(self,*a):pass
    def geturl(self):return self.url
    def read(self,n):return self.data[:n]
class Opener:
    def __init__(self,url,data):self.url=url;self.data=data;self.calls=0;self.fail=False
    def open(self,req,timeout):
        self.calls+=1
        if self.fail:raise OSError('SECRET_INTERNAL_ERROR')
        return Response(self.url,self.data)

def test_cache_expiry_fail_closed(keys):
    url='https://idp.example.org/keys'; now=[10]; opener=Opener(url,json.dumps(keys[1]).encode())
    p=CachedJWKSProvider(url,clock=lambda:now[0],opener=opener,ttl_seconds=5)
    assert p()==p() and opener.calls==1
    now[0]=16;opener.fail=True
    with pytest.raises(JWKSUnavailable,match='JWKS_UNAVAILABLE'):p()
    with pytest.raises(JWKSUnavailable):p()

def test_rotation_unknown_kid_refresh(keys):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm
    import jwt,time
    url='https://idp.example.org/keys';opener=Opener(url,json.dumps(keys[1]).encode())
    p=CachedJWKSProvider(url,opener=opener)
    v=OIDCVerifier(issuer='https://idp.example.org',audience='odmm-operations',jwks_provider=p)
    assert v.verify(signed(keys)).verified
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    public=json.loads(RSAAlgorithm.to_jwk(private.public_key()));public.update(kid='key2',alg='RS256',use='sig')
    opener.data=json.dumps({'keys':[public]}).encode()
    now=int(time.time());token=jwt.encode(dict(iss='https://idp.example.org',aud='odmm-operations',sub='alice',iat=now,nbf=now,exp=now+60,odmm_roles=['viewer']),private,algorithm='RS256',headers={'kid':'key2'})
    assert v.verify(token).verified and opener.calls==2
    with pytest.raises(PermissionError):v.verify(signed(keys))

@pytest.mark.parametrize('url',['http://idp.example.org/keys','https://user:pass@idp.example.org/keys','https://idp.example.org:8443/keys','https://idp.example.org/keys#fragment'])
def test_invalid_url(url):
    with pytest.raises(ValueError):CachedJWKSProvider(url)

def test_redirect_rejected(keys):
    op=Opener('https://attacker.example/keys',json.dumps(keys[1]).encode())
    with pytest.raises(JWKSUnavailable):CachedJWKSProvider('https://idp.example.org/keys',opener=op)()

def test_malformed_and_oversize():
    url='https://idp.example.org/keys'
    for payload in [b'{}',b'not json',b'x'*2000,json.dumps({'keys':[{'kid':'a','kty':'RSA','n':'x','e':'AQAB'}]*2}).encode()]:
        with pytest.raises(JWKSUnavailable):CachedJWKSProvider(url,opener=Opener(url,payload),max_bytes=1024)()
