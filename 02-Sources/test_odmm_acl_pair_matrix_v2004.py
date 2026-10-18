import unittest
from identity_acl import Principal,IdentityMap,ACE
from odmm_acl_pair_matrix_v2004 import plan_acl_translation,ACLPlanError
class ACLPairMatrixTests(unittest.TestCase):
 def setUp(self):
  self.src=Principal('AD','user','S-1-5-1','user-1'); self.dst=Principal('LDAP','user','uid=alice','user-1')
  self.mapping=IdentityMap([(self.src,self.dst)])
 def plan(self,aces=None,**kw):
  opts=dict(source_protocol='SMB',target_protocol='NFS',source_acl_complete=True,identity_verified=True,target_acl_capability_verified=True)
  opts.update(kw)
  return plan_acl_translation([ACE(self.src,'allow',('read',))] if aces is None else aces,self.mapping,**opts)
 def test_cross_protocol_never_certified(self):
  r=self.plan(); self.assertFalse(r['cutover_authorized']); self.assertIn('CROSS_PROTOCOL_ACL_SEMANTICS_NOT_EQUIVALENT',r['warnings']); self.assertEqual(r['status'],'REQUIRES_LIVE_EFFECTIVE_ACCESS_TESTS')
 def test_unmapped_principal_blocks(self):
  r=self.plan([ACE(Principal('AD','user','unknown','unknown'),'allow',('read',))]); self.assertEqual(r['status'],'BLOCKED'); self.assertEqual(r['blockers'][0]['reason'],'UNMAPPED_PRINCIPAL')
 def test_incomplete_evidence_blocks(self):
  r=self.plan(source_acl_complete=False,identity_verified=False,target_acl_capability_verified=False); self.assertEqual(len(r['blockers']),3)
 def test_deny_inheritance_privilege_warn(self):
  r=self.plan([ACE(self.src,'deny',('change_acl',),True)]); self.assertEqual(len(r['warnings']),4)
 def test_invalid_protocol_and_aces(self):
  with self.assertRaises(ACLPlanError): self.plan(source_protocol='S3')
  with self.assertRaises(ACLPlanError): self.plan(aces=['not-ace'])
 def test_does_not_mutate_inputs(self):
  aces=[ACE(self.src,'allow',('read',))]; before=list(aces); self.plan(aces); self.assertEqual(aces,before)
if __name__=='__main__': unittest.main()
