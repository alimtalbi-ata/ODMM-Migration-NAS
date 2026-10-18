import tempfile,unittest
from pathlib import Path
from review_identity_policy import IdentityPolicyLedger
from authenticated_review_ledger import sign_assertion
from human_approval_registry import digest,ApprovalError
K=b'k'*32
class TestIdentityPolicy(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'db.sqlite'
  r={'migration_id':'M1','status':'PENDING_HUMAN_AND_LIVE_VERIFICATION','cutover_authorized':False}; self.bundle={'report':r,'sha256':digest(r)}
 def tearDown(self): self.tmp.cleanup()
 def a(self,role='security',reviewer='alice',nonce='n1'):
  return sign_assertion(K,migration_id='M1',evidence_hash=self.bundle['sha256'],role=role,reviewer=reviewer,nonce=nonce,issued_at=10,expires_at=50)
 def setup_ledger(self,l):
  l.provision_key('k1',K,valid_from=0,valid_until=100)
  l.set_reviewer('alice','security',active=True,directory_version='v1')
 def test_valid(self):
  with IdentityPolicyLedger(self.path,issuer_secret=b'x'*32) as l:
   self.setup_ledger(l); self.assertFalse(l.record_policy_attested('M1',self.bundle,self.a(),key_id='k1',directory_version='v1',now=11)['cutover_authorized'])
 def test_revoked_key(self):
  with IdentityPolicyLedger(self.path,issuer_secret=b'x'*32) as l:
   self.setup_ledger(l); l.revoke_key('k1',now=10)
   with self.assertRaises(ApprovalError): l.record_policy_attested('M1',self.bundle,self.a(),key_id='k1',directory_version='v1',now=11)
 def test_inactive_reviewer(self):
  with IdentityPolicyLedger(self.path,issuer_secret=b'x'*32) as l:
   self.setup_ledger(l); l.set_reviewer('alice','security',active=False,directory_version='v2')
   with self.assertRaises(ApprovalError): l.record_policy_attested('M1',self.bundle,self.a(),key_id='k1',directory_version='v2',now=11)
 def test_wrong_role(self):
  with IdentityPolicyLedger(self.path,issuer_secret=b'x'*32) as l:
   self.setup_ledger(l)
   with self.assertRaises(ApprovalError): l.record_policy_attested('M1',self.bundle,self.a(role='operations'),key_id='k1',directory_version='v1',now=11)
 def test_directory_version(self):
  with IdentityPolicyLedger(self.path,issuer_secret=b'x'*32) as l:
   self.setup_ledger(l)
   with self.assertRaises(ApprovalError): l.record_policy_attested('M1',self.bundle,self.a(),key_id='k1',directory_version='v2',now=11)
 def test_key_not_yet_valid(self):
  with IdentityPolicyLedger(self.path,issuer_secret=b'x'*32) as l:
   l.provision_key('k1',K,valid_from=20,valid_until=100); l.set_reviewer('alice','security',active=True,directory_version='v1')
   with self.assertRaises(ApprovalError): l.record_policy_attested('M1',self.bundle,self.a(),key_id='k1',directory_version='v1',now=11)
 def test_bad_key(self):
  with IdentityPolicyLedger(self.path,issuer_secret=b'x'*32) as l:
   with self.assertRaises(ApprovalError): l.provision_key('k1',b'a',valid_from=0,valid_until=100)
 def test_key_duplicate(self):
  with IdentityPolicyLedger(self.path,issuer_secret=b'x'*32) as l:
   self.setup_ledger(l)
   with self.assertRaises(Exception): l.provision_key('k1',K,valid_from=0,valid_until=100)
 def test_persistence(self):
  with IdentityPolicyLedger(self.path,issuer_secret=b'x'*32) as l: self.setup_ledger(l)
  with IdentityPolicyLedger(self.path,issuer_secret=b'x'*32) as l:
   self.assertFalse(l.record_policy_attested('M1',self.bundle,self.a(),key_id='k1',directory_version='v1',now=11)['cutover_authorized'])
 def test_replay(self):
  with IdentityPolicyLedger(self.path,issuer_secret=b'x'*32) as l:
   self.setup_ledger(l); l.record_policy_attested('M1',self.bundle,self.a(),key_id='k1',directory_version='v1',now=11)
   with self.assertRaises(Exception): l.record_policy_attested('M1',self.bundle,self.a(),key_id='k1',directory_version='v1',now=12)
