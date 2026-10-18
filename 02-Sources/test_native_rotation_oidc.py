import base64,json,unittest
from types import SimpleNamespace
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes,serialization
from native_rotation_oidc import build_oidc_identity_provider

class OIDCTests(unittest.TestCase):
    def setUp(self):
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        pem=self.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        self.revoked=set()
        self.provider=build_oidc_identity_provider(issuer='https://id.example',audience='odmm',pinned_public_keys={'trusted':pem},revoked_jti=lambda j:j in self.revoked,clock=lambda:1000,leeway_seconds=0,max_token_age=300)
        self.claims={'iss':'https://id.example','aud':'odmm','sub':'operator','jti':'unique','roles':['rotation_executor'],'iat':900,'nbf':900,'exp':1100}
    def token(self,claims=None,header=None,key=None):
        enc=lambda x:base64.urlsafe_b64encode(json.dumps(x,separators=(',',':')).encode()).decode().rstrip('=')
        a=enc(header or {'alg':'RS256','kid':'trusted'});b=enc(claims or self.claims)
        sig=(key or self.key).sign((a+'.'+b).encode(),padding.PKCS1v15(),hashes.SHA256())
        return a+'.'+b+'.'+base64.urlsafe_b64encode(sig).decode().rstrip('=')
    def check(self,t):return self.provider(SimpleNamespace(headers={'authorization':'Bearer '+t}))['authenticated']
    def test_valid(self):self.assertTrue(self.check(self.token()))
    def test_bad_signature(self):self.assertFalse(self.check(self.token(key=rsa.generate_private_key(public_exponent=65537,key_size=2048))))
    def test_algorithm_confusion(self):self.assertFalse(self.check(self.token(header={'alg':'HS256','kid':'trusted'})))
    def test_unknown_kid(self):self.assertFalse(self.check(self.token(header={'alg':'RS256','kid':'unknown'})))
    def test_expired(self):self.assertFalse(self.check(self.token({**self.claims,'exp':999})))
    def test_wrong_issuer(self):self.assertFalse(self.check(self.token({**self.claims,'iss':'other'})))
    def test_wrong_audience(self):self.assertFalse(self.check(self.token({**self.claims,'aud':'other'})))
    def test_revoked(self):self.revoked.add('unique');self.assertFalse(self.check(self.token()))
    def test_revocation_failure(self):
        p=build_oidc_identity_provider(issuer='https://id.example',audience='odmm',pinned_public_keys={'trusted':self.key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)},revoked_jti=lambda j:1/0,clock=lambda:1000)
        self.assertFalse(p(SimpleNamespace(headers={'authorization':'Bearer '+self.token()}))['authenticated'])
    def test_future_token(self):self.assertFalse(self.check(self.token({**self.claims,'nbf':1200})))
    def test_overlong_lifetime(self):self.assertFalse(self.check(self.token({**self.claims,'exp':2000})))
    def test_missing_bearer(self):self.assertFalse(self.provider(SimpleNamespace(headers={}))['authenticated'])
if __name__=='__main__':unittest.main()
