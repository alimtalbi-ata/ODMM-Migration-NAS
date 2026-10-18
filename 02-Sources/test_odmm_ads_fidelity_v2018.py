import unittest, copy, hashlib
from odmm_ads_fidelity_v2018 import compare_ads_evidence,capability_matrix,extend_fidelity_report,hash_ads,digest
from odmm_migration_fidelity_report_v2011 import build_report

class TestADS(unittest.TestCase):
 def setUp(self):
  self.obs={'status':'OBSERVED','streams':[{'name':':meta:$DATA','size':3,'sha256':hashlib.sha256(b'abc').hexdigest()}]}
 def test_match(self): self.assertEqual(compare_ads_evidence(self.obs,copy.deepcopy(self.obs))['status'],'MATCH')
 def test_mismatch(self):
  x=copy.deepcopy(self.obs);x['streams'][0]['size']=4
  self.assertEqual(compare_ads_evidence(self.obs,x)['status'],'MISMATCH')
 def test_missing(self): self.assertEqual(compare_ads_evidence(self.obs,{'status':'UNVERIFIED'})['status'],'UNVERIFIED')
 def test_duplicate(self):
  x=copy.deepcopy(self.obs);x['streams']*=2
  self.assertEqual(compare_ads_evidence(x,x)['status'],'UNVERIFIED')
 def test_invalid_name(self):
  x=copy.deepcopy(self.obs);x['streams'][0]['name']='../../evil'
  self.assertEqual(compare_ads_evidence(x,x)['status'],'UNVERIFIED')
 def test_capabilities(self):
  r=capability_matrix({'ads':'SUPPORTED'},{'ads':'UNKNOWN'},required=('ads',))
  self.assertEqual(r['features'][0]['status'],'BLOCKED');self.assertFalse(r['cutover_authorized'])
 def test_capability_invalid(self):
  with self.assertRaises(ValueError): capability_matrix({'ads':'YES'},{'ads':'SUPPORTED'},required=('ads',))
 def test_extension(self):
  inv={'schema':'odmm.nas.readonly.inventory.v2006','entries':{},'entry_count':0}
  base=build_report(inv,inv)
  ads=compare_ads_evidence(self.obs,self.obs)
  result=extend_fidelity_report(base,ads_report=ads)
  self.assertEqual(result['domains']['ads']['status'],'OBSERVED_NOT_INDEPENDENTLY_ATTESTED')
  self.assertEqual(result['domains']['sparse']['status'],'UNVERIFIED')
  self.assertFalse(result['cutover_authorized'])
 def test_tamper(self):
  inv={'schema':'odmm.nas.readonly.inventory.v2006','entries':{},'entry_count':0}
  base=build_report(inv,inv);base['status']='TAMPERED'
  with self.assertRaises(ValueError): extend_fidelity_report(base)
 def test_hash_non_windows(self):
  import os
  if os.name!='nt': self.assertEqual(hash_ads('/tmp/no-file')['status'],'UNSUPPORTED_PLATFORM')

if __name__=='__main__': unittest.main()
