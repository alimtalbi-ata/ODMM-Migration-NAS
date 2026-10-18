import json
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from odmm_jwks_rotation import plan,apply
from odmm_oidc_verifier import _integer_b64
import base64

def enc(i):return base64.urlsafe_b64encode(i.to_bytes((i.bit_length()+7)//8,'big')).rstrip(b'=').decode()
def key(kid):
    n=rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_numbers()
    return {'kid':kid,'kty':'RSA','alg':'RS256','use':'sig','n':enc(n.n),'e':enc(n.e)}

class RotationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.a=key('a');cls.b=key('b')
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.old=Path(self.temp.name)/'old.json';self.new=Path(self.temp.name)/'new.json'
        self.write(self.old,[self.a]);self.write(self.new,[self.a,self.b])
        self.kw={'issuer':'https://id.example/realms/odmm','audience':'odmm'}
    def write(self,path,keys):path.write_text(json.dumps({'keys':keys}));path.chmod(0o600)
    def test_addition_plan(self):self.assertEqual(plan(self.old,self.new,**self.kw)['added'],['b'])
    def test_apply(self):
        apply(self.old,self.new,**self.kw)
        self.assertEqual(len(json.loads(self.old.read_text())['keys']),2)
    def test_retirement_requires_approval(self):
        self.write(self.new,[self.b])
        with self.assertRaisesRegex(ValueError,'RETIRE_REQUIRES'):plan(self.old,self.new,**self.kw)
        self.assertEqual(plan(self.old,self.new,retire=True,**self.kw)['removed'],['a'])
    def test_reused_kid_rejected(self):
        self.write(self.new,[self.b|{'kid':'a'}])
        with self.assertRaisesRegex(ValueError,'KID_KEY'):plan(self.old,self.new,**self.kw)
    def test_symlink_rejected(self):
        self.new.unlink();self.new.symlink_to(self.old)
        with self.assertRaisesRegex(ValueError,'JWKS_FILE_INVALID'):plan(self.old,self.new,**self.kw)
    def test_unsafe_permissions(self):
        self.new.chmod(0o666)
        with self.assertRaisesRegex(ValueError,'JWKS_UNSAFE'):plan(self.old,self.new,**self.kw)
    def test_no_change(self):
        self.write(self.new,[self.a])
        with self.assertRaisesRegex(ValueError,'NO_CHANGE'):plan(self.old,self.new,**self.kw)
    def test_invalid_jwks(self):
        self.write(self.new,[{'kid':'bad','kty':'RSA','n':'AA','e':'AQAB'}])
        with self.assertRaises((ValueError,PermissionError)):plan(self.old,self.new,**self.kw)

if __name__=='__main__':unittest.main()
