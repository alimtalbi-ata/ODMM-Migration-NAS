import unittest
from acl_loss_inventory import inventory_acl_losses,verify_acl_loss_inventory,ACLLossInventoryError
S='REVISION:1\nOWNER:S-1-5-21-100\nGROUP:S-1-5-21-200\nACL:S-1-5-21-100:ALLOWED/0x3/0x00120089'
def run(a=S,b=S,**kw):
 return inventory_acl_losses(a,b,protocol=kw.pop('protocol','SMB'),source_vendor=kw.pop('source_vendor','NetApp'),target_vendor=kw.pop('target_vendor','Dell'),**kw)
class InventoryTests(unittest.TestCase):
 def test_match_not_certified(self):
  r=run()['report'];self.assertEqual(r['status'],'STRUCTURAL_MATCH_NOT_CERTIFIED');self.assertFalse(r['cutover_authorized'])
 def test_inheritance_drift(self):
  r=run(b=S.replace('0x3/','0x2/'))['report'];self.assertEqual(r['issues'][0]['code'],'INHERITANCE_DRIFT')
 def test_missing_ace(self):
  r=run(a=S+'\nACL:S-1-5-21-100:ALLOWED/0x3/0x00120089')['report'];self.assertIn('SOURCE_ACE_MISSING_ON_TARGET',[i['code'] for i in r['issues']])
 def test_extra_ace(self):
  r=run(b=S+'\nACL:S-1-5-21-100:ALLOWED/0x3/0x00120089')['report'];self.assertIn('TARGET_EXTRA_ACE',[i['code'] for i in r['issues']])
 def test_unknown_flag(self):
  r=run(a=S.replace('0x3/','0x100/'),b=S.replace('0x3/','0x100/'))['report'];self.assertEqual(r['status'],'INDETERMINATE_ACL_TRANSLATION')
 def test_metadata_drift(self):
  r=run(b=S.replace('OWNER:S-1-5-21-100','OWNER:S-1-5-21-101'))['report'];self.assertEqual(r['status'],'BLOCKED_POTENTIAL_ACL_LOSS')
 def test_unknown_vendor(self):
  with self.assertRaises(ACLLossInventoryError):run(source_vendor='Unlisted')
 def test_invalid_protocol(self):
  with self.assertRaises(ACLLossInventoryError):run(protocol='NFSv3')
 def test_determinism(self):self.assertEqual(run(),run())
 def test_tamper(self):
  b=run();self.assertTrue(verify_acl_loss_inventory(b,S,S,protocol='SMB',source_vendor='NetApp',target_vendor='Dell'))
  b['report']['cutover_authorized']=True
  with self.assertRaises(ACLLossInventoryError):verify_acl_loss_inventory(b,S,S,protocol='SMB',source_vendor='NetApp',target_vendor='Dell')
 def test_nfs_unknown(self):
  r=run('A:z:OWNER@:rwa','A:z:OWNER@:rwa',protocol='NFSv4')['report'];self.assertEqual(r['status'],'INDETERMINATE_ACL_TRANSLATION')
 def test_vendor_labels(self):
  r=run(source_vendor='Hitachi',target_vendor='Pure')['report'];self.assertEqual(r['target_vendor'],'Pure');self.assertFalse(r['production_qualified'])
