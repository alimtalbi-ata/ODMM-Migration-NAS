import unittest,tempfile
from pathlib import Path
from odmm_session_registry_v2062 import SessionRegistry
from odmm_oidc_bridge_v2067 import verified_claims_to_session,OIDCClaimsError

class OIDCTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.now=[1000.];self.registry=SessionRegistry(Path(self.tmp.name)/'sessions.sqlite',key=b'k'*32,clock=lambda:self.now[0]);self.claims=dict(iss='https://idp.example/realm',aud='odmm',nonce='n'*24,sub='person123',iat=900,exp=1100,groups=['odmm-operator'])
 def issue(self,claims=None,**kw):return verified_claims_to_session(self.registry,claims if claims is not None else self.claims,issuer='https://idp.example/realm',audience='odmm',nonce='n'*24,clock=lambda:self.now[0],**kw)
 def test_valid(self):self.assertEqual(self.registry.resolve(self.issue())['role'],'operator')
 def test_admin_priority(self):self.assertEqual(self.registry.resolve(self.issue(dict(self.claims,groups=['odmm-viewer','odmm-admin'])))['role'],'admin')
 def test_denied_claims(self):
  changes=[{'iss':'https://other.example'},{'nonce':'x'*24},{'aud':'other'},{'sub':''},{'exp':1000},{'iat':1100},{'groups':['unknown']},{'groups':'odmm-admin'},{'aud':['odmm','other']},{'azp':'wrong','aud':['odmm','other']}]
  for change in changes:
   with self.subTest(change=change),self.assertRaises(OIDCClaimsError):self.issue(dict(self.claims,**change))
 def test_multi_audience_with_azp(self):self.assertIsNotNone(self.registry.resolve(self.issue(dict(self.claims,aud=['odmm','other'],azp='odmm'))))
 def test_expiration_bounded(self):
  token=self.issue();self.now[0]=1101;self.assertIsNone(self.registry.resolve(token))
 def test_bad_issuer_config(self):
  with self.assertRaises(OIDCClaimsError):verified_claims_to_session(self.registry,self.claims,issuer='http://idp.example',audience='odmm',nonce='n'*24)
 def test_role_mapping_fail_closed(self):
  with self.assertRaises(OIDCClaimsError):self.issue(role_mapping={'odmm-operator':'superuser'})
if __name__=='__main__':unittest.main()
