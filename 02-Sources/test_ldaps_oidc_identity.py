import base64
import json
import sqlite3
import unittest
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
from ldaps_oidc_identity import OIDCIdentityVerifier
from ldaps_identity_revocation import IdentityRevocationRegistry
from ldaps_transition_reconciliation import TransitionReconciliationError

def b64(b):return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

class OIDCTests(unittest.TestCase):
    def setUp(self):
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        pub=self.key.public_key().public_numbers()
        self.jwks={'keys':[{'kid':'one','kty':'RSA','alg':'RS256','n':b64(pub.n.to_bytes((pub.n.bit_length()+7)//8,'big')),'e':b64(pub.e.to_bytes((pub.e.bit_length()+7)//8,'big'))}]}
        self.db=sqlite3.connect(':memory:',isolation_level=None)
        self.registry=IdentityRevocationRegistry(self.db)
        self.v=OIDCIdentityVerifier(issuer='https://id.example',audience='odmm',jwks=self.jwks,registry=self.registry)
        self.claims={'iss':'https://id.example','aud':'odmm','sub':'reviewer','jti':'jwt-1','iat':100,'exp':200}
    def tearDown(self):self.db.close()
    def token(self,claims=None,head=None,key=None):
        h=b64(json.dumps(head or {'alg':'RS256','typ':'JWT','kid':'one'}).encode());p=b64(json.dumps(self.claims if claims is None else claims).encode())
        sig=(key or self.key).sign((h+'.'+p).encode(),padding.PKCS1v15(),hashes.SHA256())
        return h+'.'+p+'.'+b64(sig)
    def rejected(self,token,now=150):
        with self.assertRaises(TransitionReconciliationError):self.v.verify(token,now=now)
    def test_valid(self):self.assertTrue(self.v.verify(self.token(),now=150)['verified'])
    def test_expired(self):self.rejected(self.token(),200)
    def test_future(self):self.rejected(self.token(),99)
    def test_wrong_issuer(self):self.rejected(self.token({**self.claims,'iss':'https://other'}))
    def test_wrong_audience(self):self.rejected(self.token({**self.claims,'aud':'other'}))
    def test_multiple_audiences(self):self.assertTrue(self.v.verify(self.token({**self.claims,'aud':['x','odmm']}),now=150)['verified'])
    def test_bad_signature(self):self.rejected(self.token(key=rsa.generate_private_key(public_exponent=65537,key_size=2048)))
    def test_alg_none(self):self.rejected(self.token(head={'alg':'none','kid':'one'}))
    def test_unknown_kid(self):self.rejected(self.token(head={'alg':'RS256','kid':'missing'}))
    def test_malformed(self):self.rejected('garbage')
    def test_missing_jti(self):self.rejected(self.token({k:v for k,v in self.claims.items() if k!='jti'}))
    def test_revoked_subject(self):
        self.registry.revoke(kind='subject',identifier='reviewer',now=10);self.rejected(self.token())
    def test_revoked_issuer(self):
        self.registry.revoke(kind='issuer',identifier='https://id.example',now=10);self.rejected(self.token())
    def test_revoked_token(self):
        self.registry.revoke(kind='token',identifier='jwt-1',now=10);self.rejected(self.token())
    def test_invalid_jwks(self):
        with self.assertRaises(ValueError):OIDCIdentityVerifier(issuer='https://id.example',audience='odmm',jwks={'keys':[]})
    def test_tampered_revocation(self):
        self.registry.revoke(kind='token',identifier='other',now=10)
        self.db.execute("UPDATE identity_revocations SET identifier='jwt-1'")
        self.rejected(self.token())
