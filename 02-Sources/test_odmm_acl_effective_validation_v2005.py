import unittest
from copy import deepcopy
from identity_acl import ACE,Principal,IdentityMap
from odmm_acl_effective_validation_v2005 import validate_pair
class TestACLValidation(unittest.TestCase):
 def setUp(self):
  self.s=Principal('AD','user','S-1','alice'); self.t=Principal('LDAP','user','uid=alice','alice')
  self.mapping=IdentityMap([(self.s,self.t)])
  self.a={'aces':[ACE(self.s,'allow',('read',))],'acl_complete':True,'owner':'alice','group':'ops','size':5,'sha256':'abc','mode':420,'mtime_ns':123,'xattrs':{'user.tag':'x'},'access':{('alice','read'):True,('alice','write'):False}}
  self.b=dict(self.a,aces=[ACE(self.t,'allow',('read',))]); self.b['access']=dict(self.a['access'])
 def runpair(self,a=None,b=None,**kwargs):
  return validate_pair({'data/file':self.a if a is None else a},{'data/file':self.b if b is None else b},self.mapping,identity_verified=kwargs.get('verified',True))
 def test_matching_evidence_not_cutover(self):
  r=self.runpair(); self.assertEqual(r['blocked_count'],0); self.assertFalse(r['cutover_authorized']); self.assertFalse(r['access_tests_executed'])
 def test_acl_order_or_content_mismatch(self):
  b=dict(self.b,aces=[]); self.assertIn('ACL_ORDER_OR_CONTENT_MISMATCH',self.runpair(b=b)['files'][0]['issues'])
 def test_access_mismatch(self):
  b=dict(self.b,access={('alice','read'):False,('alice','write'):False}); self.assertIn('EFFECTIVE_ACCESS_MISMATCH',self.runpair(b=b)['files'][0]['issues'])
 def test_access_missing_or_unknown(self):
  b=dict(self.b,access={('alice','read'):None}); self.assertIn('ACCESS_TEST_NOT_ATTESTED',self.runpair(b=b)['files'][0]['issues'])
 def test_owner_and_xattrs(self):
  b=dict(self.b,owner='root',xattrs={}); issues=self.runpair(b=b)['files'][0]['issues']; self.assertIn('MISMATCH_OWNER',issues); self.assertIn('MISMATCH_XATTRS',issues)
 def test_incomplete_acl_blocks(self):
  b=dict(self.b,acl_complete=False); self.assertIn('INCOMPLETE_ACL_EVIDENCE',self.runpair(b=b)['files'][0]['issues'])
 def test_identity_not_verified(self):
  self.assertIn('IDENTITY_NOT_VERIFIED',self.runpair(verified=False)['files'][0]['issues'])
 def test_missing_target_and_unsafe_path(self):
  r=validate_pair({'../bad':self.a},{},self.mapping); self.assertEqual(r['status'],'BLOCKED'); self.assertIn('UNSAFE_RELATIVE_PATH',r['files'][0]['issues'])
 def test_empty_inventory_fail_closed(self): self.assertEqual(validate_pair({},{},self.mapping)['status'],'BLOCKED')
 def test_no_mutation_and_determinism(self):
  a=deepcopy(self.a); b=deepcopy(self.b); x=self.runpair(); self.assertEqual(x['evidence_sha256'],self.runpair()['evidence_sha256']); self.assertEqual(a,self.a); self.assertEqual(b,self.b)
if __name__=='__main__':unittest.main()
