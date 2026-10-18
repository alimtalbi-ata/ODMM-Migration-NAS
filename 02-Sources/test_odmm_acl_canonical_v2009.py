import unittest
from identity_acl import Principal,IdentityMap
from odmm_acl_canonical_v2009 import normalize_nfsv4,normalize_smb,compare_collected,ACLNormalizationError

class CanonicalTests(unittest.TestCase):
 def setUp(self):
  self.a=Principal('ad','user','100','user100');self.b=Principal('ad2','user','S-1','user100')
  self.mapping=IdentityMap([(self.a,self.b)])
  self.s={'status':'COLLECTED_UNVERIFIED','protocol':'NFSV4','entries':['A::100:r']}
  self.t={'status':'COLLECTED_UNVERIFIED','protocol':'SMB','entries':['ACL:S-1:ALLOWED/0x0/READ']}
 def run_pair(self,**kwargs):return compare_collected(self.s,self.t,{'100':self.a},{'S-1':self.b},self.mapping,**kwargs)
 def test_cross_protocol_canonical_match(self):
  x=self.run_pair(identity_verified=True);self.assertEqual(x['status'],'CANONICAL_MATCH_UNVERIFIED');self.assertFalse(x['cutover_authorized'])
 def test_identity_not_verified(self):self.assertEqual(self.run_pair()['status'],'BLOCKED')
 def test_unknown_nfs_right(self):
  with self.assertRaises(ACLNormalizationError):normalize_nfsv4(['A::100:rwatTnNcCy'],{'100':self.a})
 def test_unknown_smb_right(self):
  with self.assertRaises(ACLNormalizationError):normalize_smb(['ACL:S-1:ALLOWED/0x0/FULL'],{'S-1':self.b})
 def test_inherited_flag_rejected(self):
  with self.assertRaises(ACLNormalizationError):normalize_smb(['ACL:S-1:ALLOWED/0x1/READ'],{'S-1':self.b})
 def test_missing_identity(self):
  with self.assertRaises(ACLNormalizationError):normalize_nfsv4(['A::100:r'],{})
 def test_missing_evidence(self):
  self.s['status']='NOT_COLLECTED';self.assertEqual(self.run_pair()['status'],'BLOCKED')
 def test_deny_mismatch(self):
  self.t['entries']=['ACL:S-1:DENIED/0x0/READ'];self.assertEqual(self.run_pair(identity_verified=True)['status'],'BLOCKED')
 def test_deterministic_hash(self):self.assertEqual(self.run_pair(identity_verified=True)['evidence_sha256'],self.run_pair(identity_verified=True)['evidence_sha256'])
 def test_empty(self):
  with self.assertRaises(ACLNormalizationError):normalize_nfsv4([],{'100':self.a})
if __name__=='__main__':unittest.main()
