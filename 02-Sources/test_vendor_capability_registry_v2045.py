import unittest
from vendor_capability_registry_v2045 import qualify_pair, FIELDS
class VendorCapabilityTests(unittest.TestCase):
 def setUp(self):
  self.ibm=dict(vendor='ibm_storage_scale',version='5.2.3',protocol='NFSv4',identity_mapping_verified=True,filesystem_acl_type='NFSv4')
  self.proof=lambda *names:{n:{'source':'MATCH','target':'MATCH','comparison':'MATCH'} for n in names}
 def test_documented_pair_review_only(self): self.assertEqual(qualify_pair(self.ibm,self.ibm,('content',),self.proof('content'))['status'],'ELIGIBLE_FOR_MANUAL_REVIEW')
 def test_never_cutover(self): self.assertFalse(qualify_pair(self.ibm,self.ibm,('content',),self.proof('content'))['cutover_authorized'])
 def test_version_mismatch(self): self.assertEqual(qualify_pair(dict(self.ibm,version='6.0.1'),self.ibm,('content',),self.proof('content'))['status'],'UNVERIFIED')
 def test_missing_proof(self): self.assertIn('FIDELITY_ACL_NOT_PROVEN',qualify_pair(self.ibm,self.ibm,('acl',),{})['findings'])
 def test_partial_proof(self): self.assertEqual(qualify_pair(self.ibm,self.ibm,('acl',),{'acl':{'source':'MATCH','target':'MATCH'}})['status'],'UNVERIFIED')
 def test_unknown_vendor(self): self.assertEqual(qualify_pair(dict(self.ibm,vendor='synology_dsm'),self.ibm,('content',),self.proof('content'))['status'],'UNVERIFIED')
 def test_smb_share_acl(self): self.assertIn('source:SMB_SHARE_ACL_UNVERIFIED',qualify_pair(dict(self.ibm,protocol='SMB3'),self.ibm,('content',),self.proof('content'))['findings'])
 def test_cross_protocol(self): self.assertIn('CROSS_PROTOCOL_TRANSLATION_UNVERIFIED',qualify_pair(dict(self.ibm,protocol='SMB3',share_acl_verified=True),self.ibm,('content',),self.proof('content'))['findings'])
 def test_truenas_dataset(self):
  t=dict(vendor='truenas_scale',version='24.04',protocol='NFSv4',identity_mapping_verified=True,dataset_acl_type='POSIX')
  self.assertIn('source:DATASET_NFSV4_ACL_UNVERIFIED',qualify_pair(t,t,('acl',),self.proof('acl'))['findings'])
 def test_truenas_good_acl(self):
  t=dict(vendor='truenas_scale',version='24.04',protocol='NFSv4',identity_mapping_verified=True,dataset_acl_type='NFSv4')
  self.assertEqual(qualify_pair(t,t,('acl',),self.proof('acl'))['status'],'ELIGIBLE_FOR_MANUAL_REVIEW')
 def test_bad_requirements(self): self.assertEqual(qualify_pair(self.ibm,self.ibm,('bogus',))['status'],'BLOCKED')
 def test_empty_requirements(self): self.assertEqual(qualify_pair(self.ibm,self.ibm,())['status'],'BLOCKED')
 def test_missing_identity(self): self.assertIn('target:IDENTITY_MAPPING_UNVERIFIED',qualify_pair(self.ibm,dict(self.ibm,identity_mapping_verified=False),('content',),self.proof('content'))['findings'])
 def test_no_mutation(self):
  a=dict(self.ibm); p=self.proof('content'); qualify_pair(a,a,('content',),p); self.assertEqual(a,self.ibm);self.assertEqual(p,self.proof('content'))
if __name__=='__main__': unittest.main()
