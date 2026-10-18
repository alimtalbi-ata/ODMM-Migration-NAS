import json
import os
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from odmm_oidc_hot_reload import ReloadingOIDCVerifier

def jwk(kid):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_numbers()
    import base64
    def enc(n): return base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8,'big')).rstrip(b'=').decode()
    return {'kid':kid,'kty':'RSA','alg':'RS256','use':'sig','n':enc(key.n),'e':enc(key.e)}

class HotReloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'jwks.json'
        self.k1=jwk('old');self.k2=jwk('new')
        self.write([self.k1])
    def write(self,keys):
        self.path.write_text(json.dumps({'keys':keys}));self.path.chmod(0o600)
    def verifier(self):
        return ReloadingOIDCVerifier(issuer='https://id.example/realm',audience='odmm',jwks_path=self.path)
    def test_start_and_add_key(self):
        v=self.verifier();self.assertEqual(set(v._verifier.keys),{'old'})
        self.write([self.k1,self.k2]);self.assertTrue(v.reload());self.assertEqual(set(v._verifier.keys),{'old','new'})
    def test_retire_key(self):
        v=self.verifier();self.write([self.k2]);v.reload();self.assertEqual(set(v._verifier.keys),{'new'})
    def test_unchanged(self):
        self.assertFalse(self.verifier().reload())
    def test_corruption_fails_closed_and_recovers(self):
        v=self.verifier();self.path.write_text('not json')
        with self.assertRaises(PermissionError):v.reload()
        self.assertIsNone(v._verifier)
        self.write([self.k1]);self.assertTrue(v.reload())
    def test_missing_fails_closed(self):
        v=self.verifier();self.path.unlink()
        with self.assertRaises(PermissionError):v.reload()
        self.assertIsNone(v._verifier)
    def test_symlink_rejected(self):
        v=self.verifier();real=Path(self.tmp.name)/'real';self.path.rename(real);self.path.symlink_to(real)
        with self.assertRaises(PermissionError):v.reload()
    @unittest.skipUnless(os.name=='posix','POSIX permissions')
    def test_world_writable_rejected(self):
        v=self.verifier();self.path.chmod(0o666)
        with self.assertRaises(PermissionError):v.reload()
    def test_weak_jwk_fails_closed(self):
        v=self.verifier();self.write([{'kid':'bad','kty':'RSA','n':'AQ','e':'AQAB'}])
        with self.assertRaises(PermissionError):v.reload()
