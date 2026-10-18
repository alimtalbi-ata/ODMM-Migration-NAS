import unittest
from vendor_qualification import plan, matrix
class VendorQualificationTests(unittest.TestCase):
 def test_matrix_has_twelve_profiles(self): self.assertEqual(len(matrix()),12)
 def test_no_profile_qualified(self): self.assertTrue(all(not p['report']['production_qualified'] for p in matrix()))
 def test_reject_unknown_vendor(self):
  with self.assertRaises(ValueError): plan('Unknown','SMB','nas1')
 def test_reject_unknown_protocol(self):
  with self.assertRaises(ValueError): plan('NetApp','NFSv3','nas1')
 def test_deterministic(self): self.assertEqual(plan('IBM','SMB','nas1'),plan('IBM','SMB','nas1'))
 def test_invalid_evidence_not_accepted(self):
  r=plan('HPE','NFSv4','nas1',{'acl_capture':{'status':'PASS','sha256':'bad'}})
  self.assertEqual(r['report']['checks'][1]['status'],'NOT_QUALIFIED')
 def test_valid_evidence_still_not_certified(self):
  r=plan('Dell','SMB','nas1',{'acl_capture':{'status':'PASS','sha256':'a'*64}})
  self.assertFalse(r['report']['production_qualified'])
 def test_alias_rejects_path(self):
  with self.assertRaises(ValueError): plan('Pure','SMB','/etc/passwd')
