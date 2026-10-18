import unittest
from odmm_oidc_provider_health_v1994 import ProviderHealth

ISSUER="https://id.example/realms/odmm"
DISCOVERY={"issuer":ISSUER,"authorization_endpoint":ISSUER+"/auth","token_endpoint":ISSUER+"/token",
 "jwks_uri":ISSUER+"/certs","code_challenge_methods_supported":["S256"]}
JWKS={"keys":[{"kid":"a","kty":"RSA","n":"abc","e":"AQAB"}]}
class ProviderHealthTests(unittest.TestCase):
 def make(self,sequence):
  sequence=iter(sequence)
  def fetch(url):
   if url.endswith("openid-configuration"):
    if not next(sequence):raise TimeoutError("provider timeout")
    return DISCOVERY
   return JWKS
  return ProviderHealth(ISSUER,fetch=fetch,clock=lambda:1.0)
 def test_stable_availability(self):
  h=self.make([True,True]);self.assertEqual(h.check()["state"],"RECOVERING");self.assertEqual(h.check()["state"],"AVAILABLE")
 def test_outage_threshold(self):
  h=self.make([True,True,False,False]);h.check();h.check()
  self.assertEqual(h.check()["state"],"DEGRADED");self.assertEqual(h.check()["state"],"UNAVAILABLE")
 def test_recovery_threshold(self):
  h=self.make([False,False,True,True]);h.check();h.check()
  self.assertEqual(h.check()["state"],"RECOVERING");self.assertEqual(h.check()["state"],"AVAILABLE")
 def test_transient_failure_does_not_mark_unavailable(self):
  h=self.make([True,True,False,True,True]);[h.check() for _ in range(5)]
  self.assertEqual(h.state,"AVAILABLE")
 def test_no_sensitive_exception_text_in_report(self):
  h=self.make([False]);r=h.check()
  self.assertEqual(r["details"],{"error_type":"TimeoutError"})
  self.assertFalse(r["production_qualified"])
 def test_invalid_threshold(self):
  with self.assertRaises(ValueError):ProviderHealth(ISSUER,failure_threshold=0)
 def test_bad_discovery_is_failure(self):
  h=ProviderHealth(ISSUER,fetch=lambda url:{})
  self.assertFalse(h.check()["discovery_jwks_ok"])
if __name__=="__main__":unittest.main()
