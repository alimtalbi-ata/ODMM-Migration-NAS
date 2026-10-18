import unittest
from odmm_oidc_live_probe import qualify, validate_discovery, validate_jwks, validate_https

ISSUER = "https://id.example.invalid/realms/odmm"
DOC = {"issuer": ISSUER, "authorization_endpoint": ISSUER + "/protocol/openid-connect/auth",
       "token_endpoint": ISSUER + "/protocol/openid-connect/token",
       "jwks_uri": ISSUER + "/protocol/openid-connect/certs",
       "code_challenge_methods_supported": ["S256"]}
KEYS = {"keys": [{"kty": "RSA", "kid": "key-1", "n": "abc", "e": "AQAB"}]}

class OIDCQualificationTests(unittest.TestCase):
    def test_success(self):
        def fake(url):
            return DOC if url.endswith("openid-configuration") else KEYS
        self.assertEqual(qualify(ISSUER, fake)["status"], "PASS")
    def test_http_rejected(self):
        with self.assertRaises(ValueError): validate_https("http://id.example.invalid")
    def test_credentials_rejected(self):
        with self.assertRaises(ValueError): validate_https("https://u:p@id.example.invalid")
    def test_issuer_mismatch(self):
        with self.assertRaises(ValueError): validate_discovery(ISSUER, dict(DOC, issuer="https://evil.invalid"))
    def test_pkce_required(self):
        with self.assertRaises(ValueError): validate_discovery(ISSUER, dict(DOC, code_challenge_methods_supported=[]))
    def test_cross_host_jwks(self):
        with self.assertRaises(ValueError): validate_discovery(ISSUER, dict(DOC, jwks_uri="https://evil.invalid/keys"))
    def test_duplicate_key_rejected(self):
        with self.assertRaises(ValueError): validate_jwks({"keys": KEYS["keys"] * 2})
    def test_empty_keyset_rejected(self):
        with self.assertRaises(ValueError): validate_jwks({"keys": []})
    def test_incomplete_key_rejected(self):
        with self.assertRaises(ValueError): validate_jwks({"keys": [{"kid":"a","kty":"RSA"}]})

if __name__ == "__main__": unittest.main()
