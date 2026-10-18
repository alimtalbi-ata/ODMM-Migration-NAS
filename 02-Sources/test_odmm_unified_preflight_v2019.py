import unittest
from odmm_unified_preflight_v2019 import evaluate,verify
H='a'*64
class TestPreflight(unittest.TestCase):
 def setUp(self):
  self.a={'content':'SUPPORTED','acl':'SUPPORTED'}
 def test_nominal_still_blocked(self):
  r=evaluate(self.a,self.a,required=['content'],evidence={'content':{'status':'MATCH','source_sha256':H,'target_sha256':H,'independently_attested':True}})
  self.assertTrue(verify(r));self.assertFalse(r['cutover_authorized']);self.assertEqual(r['domains'][0]['status'],'BLOCKED_PENDING_LIVE_VALIDATION')
 def test_unknown_target(self):
  r=evaluate(self.a,{},required=['acl']);self.assertIn('TARGET_CAPABILITY_NOT_PROVEN',r['domains'][0]['issues'])
 def test_missing_evidence(self):
  r=evaluate(self.a,self.a,required=['content']);self.assertIn('INDEPENDENT_FIDELITY_EVIDENCE_MISSING',r['domains'][0]['issues'])
 def test_invalid_attestation(self):
  r=evaluate(self.a,self.a,required=['content'],evidence={'content':{'status':'MATCH','source_sha256':H,'target_sha256':H,'independently_attested':'true'}})
  self.assertEqual(r['domains'][0]['evidence_status'],'UNVERIFIED')
 def test_unknown_domain(self):
  with self.assertRaises(ValueError):evaluate(self.a,self.a,required=['magic'])
 def test_duplicate_domain(self):
  with self.assertRaises(ValueError):evaluate(self.a,self.a,required=['acl','acl'])
 def test_invalid_capability(self):
  with self.assertRaises(ValueError):evaluate({'acl':'MAYBE'},self.a,required=['acl'])
 def test_external_explicit(self):
  r=evaluate(self.a,self.a,required=['acl'],strategy='EXPLICIT_EXTERNAL');self.assertTrue(r['explicit_external_selection_required']);self.assertFalse(r['native_engine_default'])
 def test_no_silent_fallback(self):
  self.assertFalse(evaluate(self.a,self.a,required=['acl'])['silent_fallback_allowed'])
 def test_tamper(self):
  r=evaluate(self.a,self.a,required=['acl']);r['domains'][0]['status']='PASS';self.assertFalse(verify(r))
 def test_empty(self):
  with self.assertRaises(ValueError):evaluate(self.a,self.a,required=[])
 def test_no_nas_write(self):
  self.assertFalse(evaluate(self.a,self.a,required=['acl'])['writes_to_nas'])
if __name__=='__main__':unittest.main()
