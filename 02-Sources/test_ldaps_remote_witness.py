import hashlib
import hmac
import unittest
from unittest.mock import patch
from ldaps_remote_witness import RemoteWitnessVerifier, canonical
from ldaps_ipc_persistent_identity import IdentityPinError

KEY=b'k'*32
HEAD='a'*64

def client(transport, **kwargs):
    return RemoteWitnessVerifier(host='witness.example',port=443,cafile='ca.pem',certfile='client.pem',keyfile='client.key',witness_key=KEY,transport=transport,**kwargs)

def signed(req, *, count=4, head=HEAD, nonce=None):
    body={'version':1,'nonce':req['nonce'] if nonce is None else nonce,'count':count,'last_mac':head}
    return {**body,'hmac_sha256':hmac.new(KEY,canonical(body),hashlib.sha256).hexdigest()}

class Tests(unittest.TestCase):
    def test_success(self):
        self.assertEqual(client(signed).verify(expected_count=4,expected_last_mac=HEAD)['status'],'REMOTE_WITNESS_VERIFIED')
    def test_replayed_nonce(self):
        with self.assertRaisesRegex(IdentityPinError,'RESPONSE_INVALID'):
            client(lambda req:signed(req,nonce='old')).verify(expected_count=4,expected_last_mac=HEAD)
    def test_divergent_count(self):
        with self.assertRaisesRegex(IdentityPinError,'DIVERGENCE'):
            client(lambda req:signed(req,count=3)).verify(expected_count=4,expected_last_mac=HEAD)
    def test_divergent_head(self):
        with self.assertRaisesRegex(IdentityPinError,'DIVERGENCE'):
            client(lambda req:signed(req,head='b'*64)).verify(expected_count=4,expected_last_mac=HEAD)
    def test_bad_mac(self):
        with self.assertRaisesRegex(IdentityPinError,'AUTH_FAILED'):
            client(lambda req:{**signed(req),'hmac_sha256':'0'*64}).verify(expected_count=4,expected_last_mac=HEAD)
    def test_timeout(self):
        with self.assertRaisesRegex(IdentityPinError,'UNAVAILABLE'):
            client(lambda req:(_ for _ in ()).throw(TimeoutError())).verify(expected_count=4,expected_last_mac=HEAD)
    def test_invalid_response(self):
        with self.assertRaisesRegex(IdentityPinError,'RESPONSE_INVALID'):
            client(lambda req:{'status':'ok'}).verify(expected_count=4,expected_last_mac=HEAD)
    def test_no_client_cert(self):
        with self.assertRaisesRegex(IdentityPinError,'MTLS_REQUIRED'):
            RemoteWitnessVerifier(host='x',port=443,cafile='ca',certfile='',keyfile='key',witness_key=KEY)
    def test_short_key(self):
        with self.assertRaisesRegex(IdentityPinError,'KEY_TOO_SHORT'):
            RemoteWitnessVerifier(host='x',port=443,cafile='ca',certfile='cert',keyfile='key',witness_key=b'x')
    def test_invalid_expectation(self):
        with self.assertRaisesRegex(IdentityPinError,'EXPECTATION_INVALID'):
            client(signed).verify(expected_count=True,expected_last_mac=HEAD)
    def test_no_publish(self):
        self.assertFalse(hasattr(client(signed),'publish'))
    def test_unique_nonce(self):
        seen=[]
        def transport(req):
            seen.append(req['nonce']);return signed(req)
        c=client(transport)
        c.verify(expected_count=4,expected_last_mac=HEAD)
        c.verify(expected_count=4,expected_last_mac=HEAD)
        self.assertNotEqual(seen[0],seen[1])
