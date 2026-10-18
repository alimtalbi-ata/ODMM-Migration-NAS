import unittest
from acl_portability_review import review_acl_portability,verify_acl_portability,ACLPortabilityError
S='REVISION:1\nOWNER:S-1-5-21-100\nGROUP:S-1-5-21-200\nACL:S-1-5-21-100:ALLOWED/0x3/0x00120089'
class PortabilityTests(unittest.TestCase):
 def test_smb_match(self):
  self.assertEqual(review_acl_portability(S,S,protocol='SMB')['report']['status'],'STRUCTURAL_MATCH_ONLY')
 def test_smb_inheritance_drift(self):
  self.assertEqual(review_acl_portability(S,S.replace('0x3/','0x2/'),protocol='SMB')['report']['status'],'BLOCKED_ACL_PORTABILITY_DRIFT')
 def test_unknown_smb_bits(self):
  x=S.replace('0x3/','0x100/'); self.assertEqual(review_acl_portability(x,x,protocol='SMB')['report']['status'],'INDETERMINATE_PORTABILITY')
 def test_nfs_missing_metadata(self):
  self.assertEqual(review_acl_portability('A:fd:OWNER@:rwa','A:fd:OWNER@:rwa',protocol='NFSv4')['report']['status'],'INDETERMINATE_PORTABILITY')
 def test_nfs_drift(self):
  self.assertEqual(review_acl_portability('A:fd:OWNER@:rwa','A:f:OWNER@:rwa',protocol='NFSv4')['report']['status'],'BLOCKED_ACL_PORTABILITY_DRIFT')
 def test_unknown_nfs_flag(self):
  self.assertTrue(review_acl_portability('A:z:OWNER@:rwa','A:z:OWNER@:rwa',protocol='NFSv4')['report']['unrecognized_flags_present'])
 def test_invalid_protocol(self):
  with self.assertRaises(ACLPortabilityError): review_acl_portability(S,S,protocol='NFSv3')
 def test_invalid_acl(self):
  with self.assertRaises(ACLPortabilityError): review_acl_portability('broken',S,protocol='SMB')
 def test_tamper(self):
  b=review_acl_portability(S,S,protocol='SMB'); self.assertTrue(verify_acl_portability(b,S,S,protocol='SMB'))
  b['report']['cutover_authorized']=True
  with self.assertRaises(ACLPortabilityError): verify_acl_portability(b,S,S,protocol='SMB')
 def test_determinism(self):
  self.assertEqual(review_acl_portability(S,S,protocol='SMB'),review_acl_portability(S,S,protocol='SMB'))
 def test_no_automatic_approval(self):
  r=review_acl_portability(S,S,protocol='SMB')['report']; self.assertFalse(r['cutover_authorized']);self.assertFalse(r['production_qualified'])
if __name__=='__main__':unittest.main()
