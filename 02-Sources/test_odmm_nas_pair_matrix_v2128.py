import unittest
from odmm_nas_pair_matrix_v2128 import *
class TestMatrix(unittest.TestCase):
 def test_count(self): self.assertEqual(len(matrix()),15*14)
 def test_same_vendor_count(self): self.assertEqual(len(matrix(include_same_vendor=True)),225)
 def test_unique(self): self.assertEqual(len({p.direction for p in matrix()}),210)
 def test_bidirectional(self):
  directions={p.direction for p in matrix()}
  self.assertIn('NETAPP_ONTAP_TO_PURE_FLASHBLADE',directions)
  self.assertIn('PURE_FLASHBLADE_TO_NETAPP_ONTAP',directions)
  self.assertIn('DELL_ONEFS_TO_IBM_STORAGE_SCALE',directions)
 def test_aliases(self):
  self.assertEqual(normalize_vendor('Isilon'),'dell_onefs')
  self.assertEqual(normalize_vendor('AFF'),'netapp_ontap')
  self.assertEqual(normalize_vendor('quTS'),'qnap_qts')
 def test_fail_closed(self):
  self.assertTrue(all(p.status=='BLOCKED' and not p.cutover_authorized for p in matrix()))
 def test_invalid_vendor(self):
  with self.assertRaises(ValueError): normalize_vendor('invented')
 def test_invalid_protocol(self):
  with self.assertRaises(ValueError): matrix(protocol='FTP')
 def test_incomplete(self):
  p=plan_pair({'vendor':'netapp','protocol':'NFS4'}, {'vendor':'onefs','protocol':'SMB3'})
  self.assertIn('SOURCE_INVENTORY_INCOMPLETE',p.blockers)
  self.assertIn('PROTOCOL_TRANSLATION_NOT_QUALIFIED',p.blockers)
 def test_no_proof_trust(self):
  p=plan_pair({'vendor':'netapp','protocol':'SMB3','namespace':'x','inventory_complete':True,'cutover_authorized':True},
              {'vendor':'pure','protocol':'SMB3','namespace':'y','inventory_complete':True,'cutover_authorized':True})
  self.assertFalse(p.cutover_authorized)
  self.assertIn('ACL_FIDELITY_NOT_VERIFIED',p.blockers)
 def test_report(self):
  r=matrix_report()
  self.assertEqual(r['count'],210)
  self.assertEqual(r['certified_pairs'],0)
