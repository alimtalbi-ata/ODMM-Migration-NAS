"""Author: Abdelhalim Talbi."""
import json
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from odmm_jwks_atomic_publish import publish
from odmm_oidc_hot_reload import ReloadingOIDCVerifier
import base64

def b64(n):
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8,'big')).rstrip(b'=').decode()

def key(kid):
    k=rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_numbers()
    return {'kid':kid,'kty':'RSA','alg':'RS256','use':'sig','n':b64(k.n),'e':b64(k.e)}

class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.src=Path(self.tmp.name)/'candidate';self.dst=Path(self.tmp.name)/'active'
        self.issuer='https://id.example/realm';self.audience='odmm'
    def write(self, keys): self.src.write_text(json.dumps({'keys':keys}))
    def apply(self): return publish(self.src,self.dst,issuer=self.issuer,audience=self.audience)
    def test_publish_and_reload(self):
        self.write([key('one')]);self.apply()
        v=ReloadingOIDCVerifier(issuer=self.issuer,audience=self.audience,jwks_path=self.dst)
        self.assertEqual(set(v._verifier.keys),{'one'})
        self.write([key('two')]);self.apply();v.reload()
        self.assertEqual(set(v._verifier.keys),{'two'})
    def test_invalid_preserves_previous(self):
        self.write([key('good')]);self.apply();before=self.dst.read_bytes()
        self.src.write_text('invalid')
        with self.assertRaises(ValueError): self.apply()
        self.assertEqual(self.dst.read_bytes(),before)
    def test_symlink_source_rejected(self):
        self.write([key('good')]);link=Path(self.tmp.name)/'link';link.symlink_to(self.src)
        with self.assertRaises(PermissionError):publish(link,self.dst,issuer=self.issuer,audience=self.audience)
    def test_symlink_destination_rejected(self):
        self.write([key('good')]);self.dst.symlink_to(self.src)
        with self.assertRaises(PermissionError):self.apply()
    def test_missing_destination_directory(self):
        self.write([key('good')])
        with self.assertRaises(FileNotFoundError):publish(self.src,Path(self.tmp.name)/'missing'/'active',issuer=self.issuer,audience=self.audience)
    def test_oversized_rejected(self):
        self.src.write_bytes(b'x'*(1024*1024+1))
        with self.assertRaises(ValueError):self.apply()
if __name__=='__main__': unittest.main()
