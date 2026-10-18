import unittest
from odmm_oidc_lab_preflight import validate_config

BASE={'ODMM_OIDC_ISSUER':'https://id.example.test/realms/odmm',
      'ODMM_OIDC_AUTHORIZATION_ENDPOINT':'https://id.example.test/realms/odmm/protocol/openid-connect/auth',
      'ODMM_OIDC_TOKEN_ENDPOINT':'https://id.example.test/realms/odmm/protocol/openid-connect/token',
      'ODMM_PUBLIC_ORIGIN':'https://odmm.example.test',
      'ODMM_OIDC_REDIRECT_URI':'https://odmm.example.test/auth/callback',
      'ODMM_OIDC_CLIENT_ID':'odmm-browser'}
class LabPreflightTests(unittest.TestCase):
    def test_valid(self): self.assertTrue(validate_config(BASE))
    def test_missing(self):
        with self.assertRaisesRegex(ValueError,'MISSING'): validate_config({})
    def test_http(self):
        with self.assertRaisesRegex(ValueError,'INVALID_HTTPS_URL'): validate_config(dict(BASE,ODMM_OIDC_TOKEN_ENDPOINT='http://id.example.test/token'))
    def test_redirect_mismatch(self):
        with self.assertRaisesRegex(ValueError,'REDIRECT_MISMATCH'): validate_config(dict(BASE,ODMM_OIDC_REDIRECT_URI='https://odmm.example.test/evil'))
    def test_credentials_in_url(self):
        with self.assertRaisesRegex(ValueError,'INVALID_HTTPS_URL'): validate_config(dict(BASE,ODMM_OIDC_ISSUER='https://u:p@id.example.test'))
    def test_fragment(self):
        with self.assertRaisesRegex(ValueError,'INVALID_HTTPS_URL'): validate_config(dict(BASE,ODMM_PUBLIC_ORIGIN='https://odmm.example.test/#fragment'))
    def test_empty_client(self):
        with self.assertRaisesRegex(ValueError,'EMPTY_CLIENT_ID'): validate_config(dict(BASE,ODMM_OIDC_CLIENT_ID=' '))
    def test_private_ip(self):
        with self.assertRaisesRegex(ValueError,'NON_PUBLIC_IP'): validate_config(dict(BASE,ODMM_OIDC_ISSUER='https://127.0.0.1/realms/odmm'))
if __name__=='__main__': unittest.main()
