import unittest
from vendor_offline_collectors_v2047 import normalize_export
from vendor_evidence_profiles_v2046 import REQUIRED_OBSERVATIONS
class TestOffline(unittest.TestCase):
 def test_three_adapters(self):
  for v in ('netapp_ontap','dell_powerscale','truenas_scale'):
   self.assertEqual(normalize_export({'vendor':v,'observed':{}})['endpoint']['vendor'],v)
 def test_unknown_refused(self):
  with self.assertRaises(ValueError):normalize_export({'vendor':'unknown','observed':{}})
 def test_no_claim_of_proof(self):
  o=normalize_export({'vendor':'netapp_ontap','observed':{'acl_model':'NFSv4'}})
  self.assertFalse(o['endpoint']['capabilities_observed']);self.assertFalse(o['cutover_authorized'])
 def test_missing_list(self):
  self.assertIn('software_version',normalize_export({'vendor':'truenas_scale','observed':{}})['missing'])
 def test_invalid(self):
  with self.assertRaises(ValueError):normalize_export({'vendor':'truenas_scale','observed':[]})
 def test_ignore_user_proof_flags(self):
  o=normalize_export({'vendor':'truenas_scale','observed':{'capabilities_observed':True,'datasheet_version_verified':True}})
  self.assertFalse(o['endpoint']['datasheet_version_verified'])
 def test_complete_still_unverified(self):
  o=normalize_export({'vendor':'dell_powerscale','observed':{k:'value' for k in REQUIRED_OBSERVATIONS}})
  self.assertEqual(o['missing'],[]);self.assertEqual(o['status'],'UNVERIFIED')
if __name__=='__main__':unittest.main()
