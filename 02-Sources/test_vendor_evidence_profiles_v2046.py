import unittest
from vendor_evidence_profiles_v2046 import evaluate,VENDORS,REQUIRED_OBSERVATIONS
class Tests(unittest.TestCase):
 def setUp(self):
  self.e={k:'observed' for k in REQUIRED_OBSERVATIONS};self.e.update(vendor='netapp_ontap',capabilities_observed=True,datasheet_version_verified=True)
  self.p={'content':{'source':'MATCH','target':'MATCH','comparison':'MATCH'}}
 def test_all_vendor_catalog(self):self.assertGreaterEqual(len(VENDORS),14)
 def test_verified_evidence_review_only(self):self.assertEqual(evaluate(self.e,self.e,('content',),self.p)['status'],'ELIGIBLE_FOR_MANUAL_REVIEW')
 def test_never_cutover(self):self.assertFalse(evaluate(self.e,self.e,('content',),self.p)['cutover_authorized'])
 def test_unknown_vendor(self):self.assertIn('source:UNKNOWN_VENDOR',evaluate(dict(self.e,vendor='unknown'),self.e,('content',),self.p)['findings'])
 def test_missing_observation(self):self.assertIn('source:MISSING_ACL_MODEL',evaluate(dict(self.e,acl_model=None),self.e,('content',),self.p)['findings'])
 def test_version_unverified(self):self.assertIn('target:DOCUMENT_VERSION_NOT_VERIFIED',evaluate(self.e,dict(self.e,datasheet_version_verified=False),('content',),self.p)['findings'])
 def test_no_live_probe(self):self.assertIn('source:CAPABILITIES_NOT_OBSERVED',evaluate(dict(self.e,capabilities_observed=False),self.e,('content',),self.p)['findings'])
 def test_translation(self):self.assertIn('TRANSLATION_ACL_MODEL_NOT_PROVEN',evaluate(dict(self.e,acl_model='NFSv4'),dict(self.e,acl_model='POSIX'),('content',),self.p)['findings'])
 def test_missing_proof(self):self.assertIn('FIDELITY_ACL_NOT_PROVEN',evaluate(self.e,self.e,('acl',),self.p)['findings'])
 def test_bad_requirements(self):self.assertEqual(evaluate(self.e,self.e,())['status'],'BLOCKED')
 def test_does_not_mutate(self):
  a=dict(self.e);p={'content':dict(self.p['content'])};evaluate(a,a,('content',),p);self.assertEqual(a,self.e);self.assertEqual(p,self.p)
if __name__=='__main__':unittest.main()
