import unittest, base64, json, time
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
from odmm_oidc_verifier import OIDCVerifier

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
class OIDCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        p=cls.key.public_key().public_numbers()
        cls.jwks={'keys':[{'kty':'RSA','kid':'key1','alg':'RS256','n':b64(p.n.to_bytes((p.n.bit_length()+7)//8,'big')),'e':b64(p.e.to_bytes((p.e.bit_length()+7)//8,'big'))}]}
    def verifier(self): return OIDCVerifier(issuer='https://id.example',audience='odmm',jwks=self.jwks,clock=lambda:1000)
    def token(self, payload=None, header=None):
        h={'alg':'RS256','typ':'JWT','kid':'key1'} if header is None else header
        p={'iss':'https://id.example','aud':'odmm','exp':2000,'sub':'alice','roles':['viewer']} if payload is None else payload
        a=b64(json.dumps(h).encode()); b=b64(json.dumps(p).encode())
        sig=self.key.sign((a+'.'+b).encode(),padding.PKCS1v15(),hashes.SHA256())
        return a+'.'+b+'.'+b64(sig)
    def test_valid(self): self.assertEqual(self.verifier().verify(self.token()).subject,'alice')
    def test_expired(self):
        with self.assertRaises(PermissionError): self.verifier().verify(self.token({'iss':'https://id.example','aud':'odmm','exp':999,'sub':'alice','roles':['viewer']}))
    def test_bad_audience(self):
        with self.assertRaises(PermissionError): self.verifier().verify(self.token({'iss':'https://id.example','aud':'other','exp':2000,'sub':'alice','roles':['viewer']}))
    def test_bad_issuer(self):
        with self.assertRaises(PermissionError): self.verifier().verify(self.token({'iss':'https://other','aud':'odmm','exp':2000,'sub':'alice','roles':['viewer']}))
    def test_algorithm_none(self):
        with self.assertRaises(PermissionError): self.verifier().verify(self.token(header={'alg':'none','kid':'key1'}))
    def test_tampered(self):
        tok=self.token(); a,b,c=tok.split('.'); b=b64(json.dumps({'sub':'admin'}).encode())
        with self.assertRaises(PermissionError): self.verifier().verify(a+'.'+b+'.'+c)
    def test_unknown_role(self):
        with self.assertRaises(PermissionError): self.verifier().verify(self.token({'iss':'https://id.example','aud':'odmm','exp':2000,'sub':'alice','roles':['root']}))
    def test_unknown_key(self):
        with self.assertRaises(PermissionError): self.verifier().verify(self.token(header={'alg':'RS256','kid':'other'}))
    def test_no_bearer(self):
        class R: headers={}
        with self.assertRaises(PermissionError): self.verifier().resolve_request(R())
    def test_duplicate_kid(self):
        with self.assertRaises(ValueError): OIDCVerifier(issuer='https://id.example',audience='odmm',jwks={'keys':self.jwks['keys']*2})
    def test_weak_key(self):
        with self.assertRaises(ValueError): OIDCVerifier(issuer='https://id.example',audience='odmm',jwks={'keys':[dict(self.jwks['keys'][0],n=b64(b'\x01'*16))]})
