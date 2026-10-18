"""Signed JWT rotation and pinned JWKS outage tests. Author: Abdelhalim Talbi."""
import base64, json, os, tempfile, time, unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from odmm_oidc_hot_reload import ReloadingOIDCVerifier

def b64(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
def num(n): return b64(n.to_bytes((n.bit_length()+7)//8,'big'))
def pair(kid):
    priv=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    pub=priv.public_key().public_numbers()
    return priv,dict(kid=kid,kty='RSA',alg='RS256',use='sig',n=num(pub.n),e=num(pub.e))
def token(priv,kid):
    header=b64(json.dumps(dict(alg='RS256',typ='JWT',kid=kid)).encode())
    claims=b64(json.dumps(dict(iss='https://id.example/realm',aud='odmm',sub='operator-1',roles=['operator'],exp=int(time.time())+300)).encode())
    payload=header+'.'+claims
    return payload+'.'+b64(priv.sign(payload.encode(),padding.PKCS1v15(),hashes.SHA256()))
class RotationOutageTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.path=Path(t.name)/'jwks.json'
        self.old,self.oldjwk=pair('old');self.new,self.newjwk=pair('new')
        self.write([self.oldjwk])
        self.v=ReloadingOIDCVerifier(issuer='https://id.example/realm',audience='odmm',jwks_path=self.path)
    def write(self,keys):
        self.path.write_text(json.dumps(dict(keys=keys)));self.path.chmod(0o600)
    def test_old_token_valid(self): self.assertEqual(self.v.verify(token(self.old,'old')).subject,'operator-1')
    def test_new_key_untrusted_before_rotation(self):
        with self.assertRaises(PermissionError):self.v.verify(token(self.new,'new'))
    def test_overlap_and_retirement(self):
        self.write([self.oldjwk,self.newjwk])
        self.assertEqual(self.v.verify(token(self.old,'old')).subject,'operator-1')
        self.assertEqual(self.v.verify(token(self.new,'new')).subject,'operator-1')
        self.write([self.newjwk])
        with self.assertRaises(PermissionError):self.v.verify(token(self.old,'old'))
        self.assertEqual(self.v.verify(token(self.new,'new')).subject,'operator-1')
    def test_missing_file_fails_closed_and_recovers(self):
        self.path.unlink()
        with self.assertRaises(PermissionError):self.v.verify(token(self.old,'old'))
        self.assertIsNone(self.v._verifier)
        self.write([self.oldjwk])
        self.assertEqual(self.v.verify(token(self.old,'old')).subject,'operator-1')
    def test_corrupt_file_fails_closed_and_recovers(self):
        self.path.write_text('not json')
        with self.assertRaises(PermissionError):self.v.verify(token(self.old,'old'))
        self.assertIsNone(self.v._verifier)
        self.write([self.oldjwk])
        self.assertEqual(self.v.verify(token(self.old,'old')).subject,'operator-1')
    @unittest.skipUnless(os.name=='posix','POSIX permission checks')
    def test_world_writable_file_fails_closed(self):
        self.path.chmod(0o666)
        with self.assertRaises(PermissionError):self.v.verify(token(self.old,'old'))
        self.assertIsNone(self.v._verifier)
