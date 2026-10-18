import json
import pathlib
import unittest
ROOT = pathlib.Path(__file__).resolve().parent / "deploy" / "oidc-lab"
class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.realm=json.loads((ROOT/"realm/odmm-realm.json").read_text())
        cls.compose=(ROOT/"compose.qualify.yaml").read_text()
        cls.nginx=(ROOT/"nginx-keycloak.conf").read_text()
    def test_realm_enabled(self): self.assertTrue(self.realm["enabled"])
    def test_public_client_pkce(self):
        c=self.realm["clients"][0]
        self.assertTrue(c["publicClient"])
        self.assertEqual(c["attributes"]["pkce.code.challenge.method"],"S256")
    def test_implicit_disabled(self): self.assertFalse(self.realm["clients"][0]["implicitFlowEnabled"])
    def test_password_grant_disabled(self): self.assertFalse(self.realm["clients"][0]["directAccessGrantsEnabled"])
    def test_no_wildcard_redirect(self): self.assertNotIn("*",str(self.realm["clients"][0]["redirectUris"]))
    def test_no_test_users(self): self.assertNotIn("users",self.realm)
    def test_loopback_tls(self): self.assertIn("127.0.0.1:8443:8443",self.compose)
    def test_no_keycloak_port_override(self): self.assertNotIn("8080:8080",self.compose)
    def test_digest_required(self): self.assertIn("NGINX_IMAGE:?",self.compose)
    def test_tls_minimum(self): self.assertIn("TLSv1.2 TLSv1.3",self.nginx)
    def test_import_realm(self): self.assertIn("--import-realm",self.compose)
if __name__=="__main__": unittest.main()
