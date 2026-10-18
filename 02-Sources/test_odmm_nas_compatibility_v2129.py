import unittest
from odmm_nas_compatibility_v2129 import qualify_pair,compatibility_matrix

def ep(v='netapp',p=('NFS4',),verified=True,nas=True):
 return {'vendor':v,'protocols':p,'nas_capable':nas,'evidence':{'id':v+'-inventory-1','verified':verified}}

class TestCompatibility(unittest.TestCase):
 def test_conditional_not_supported(self):
  r=qualify_pair(ep(),ep('pure'))
  self.assertEqual(r.classification,'CONDITIONAL');self.assertFalse(r.certified);self.assertFalse(r.cutover_authorized)
 def test_onefs_reverse(self):
  r=qualify_pair(ep('onefs'),ep('netapp'));self.assertEqual(r.classification,'CONDITIONAL')
 def test_no_common_protocol(self):
  r=qualify_pair(ep(p=('NFS3',)),ep('pure',('SMB3',)))
  self.assertEqual(r.classification,'NOT_QUALIFIED');self.assertIn('NO_COMMON_PROTOCOL',r.blockers)
 def test_unverified(self):
  r=qualify_pair(ep(verified=False),ep('pure'))
  self.assertEqual(r.classification,'NOT_QUALIFIED')
 def test_not_applicable_only_with_verified(self):
  self.assertEqual(qualify_pair(ep(nas=False),ep('pure')).classification,'NOT_APPLICABLE')
  self.assertEqual(qualify_pair(ep(nas=False,verified=False),ep('pure')).classification,'NOT_QUALIFIED')
 def test_missing_nas(self):
  self.assertEqual(qualify_pair(ep(nas=None),ep('pure')).classification,'NOT_QUALIFIED')
 def test_reject_unknown_vendor(self):
  with self.assertRaises(ValueError):qualify_pair(ep('fiction'),ep('pure'))
 def test_reject_invalid_protocol(self):
  with self.assertRaises(ValueError):qualify_pair(ep(p=('FTP',)),ep('pure'))
 def test_reject_missing_evidence(self):
  a=ep();a.pop('evidence')
  with self.assertRaises(ValueError):qualify_pair(a,ep('pure'))
 def test_reject_empty_evidence_id(self):
  a=ep();a['evidence']['id']=''
  with self.assertRaises(ValueError):qualify_pair(a,ep('pure'))
 def test_claimed_all_proofs_still_blocked(self):
  args=dict(identity_mapping_verified=True,acl_verified=True,effective_access_verified=True,metadata_verified=True,native_engine_verified=True,rollback_verified=True,distributed_fencing_verified=True)
  r=qualify_pair(ep(),ep('pure'),**args)
  self.assertFalse(r.cutover_authorized);self.assertIn('NO_INDEPENDENT_VENDOR_FIRMWARE_CERTIFICATION',r.blockers)
 def test_matrix(self):
  r=compatibility_matrix();self.assertEqual(r['directions'],210);self.assertEqual(r['supported'],0)
 def test_bad_matrix_protocol(self):
  with self.assertRaises(ValueError):compatibility_matrix(protocol='X')
