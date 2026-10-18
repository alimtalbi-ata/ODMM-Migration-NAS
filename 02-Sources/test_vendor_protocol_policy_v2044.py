import unittest
from vendor_protocol_policy_v2044 import qualify
class VendorPolicyTests(unittest.TestCase):
 def setUp(self):
  self.n={'vendor':'netapp_ontap','protocol':'NFSv4','version':'9.15','security_style':'UNIX','identity_mapping_verified':True,'acl_evidence':True,'metadata_evidence':True}
 def q(self,a=None,b=None,required=('content',),evidence=None):
  return qualify(self.n if a is None else a,self.n if b is None else b,required=required,evidence={'content':'MATCH'} if evidence is None else evidence)
 def test_known_same_vendor_review_only(self): self.assertEqual(self.q()['status'],'ELIGIBLE_FOR_MANUAL_REVIEW')
 def test_no_cutover(self): self.assertFalse(self.q()['cutover_authorized'])
 def test_unknown_vendor(self): self.assertEqual(self.q(dict(self.n,vendor='unknown'))['status'],'UNVERIFIED')
 def test_mixed_style(self): self.assertEqual(self.q(dict(self.n,security_style='mixed'))['status'],'UNVERIFIED')
 def test_cross_protocol(self): self.assertEqual(self.q(b=dict(self.n,protocol='SMB3'))['status'],'UNVERIFIED')
 def test_cross_vendor(self): self.assertEqual(self.q(b=dict(self.n,vendor='dell_powerscale'))['status'],'UNVERIFIED')
 def test_acl_missing(self): self.assertEqual(self.q(a=dict(self.n,acl_evidence=False),required=('acl',),evidence={'acl':'MATCH'})['status'],'UNVERIFIED')
 def test_missing_field_evidence(self): self.assertEqual(self.q(evidence={})['status'],'UNVERIFIED')
 def test_missing_profile(self): self.assertEqual(self.q(a={})['status'],'UNVERIFIED')
 def test_invalid_protocol(self): self.assertEqual(self.q(a=dict(self.n,protocol='XYZ'))['status'],'UNVERIFIED')
 def test_s3_conflict(self): self.assertEqual(self.q(a=dict(self.n,vendor='aws_s3'))['status'],'BLOCKED')
 def test_empty_required(self): self.assertEqual(self.q(required=())['status'],'BLOCKED')
if __name__=='__main__': unittest.main()
