import copy
import unittest
from migration_acl_risk_report import assess_migration_acl_risk, verify_migration_acl_risk, MigrationACLRiskError
S='REVISION:1\nOWNER:S-1-5-21-100\nGROUP:S-1-5-21-200\nACL:S-1-5-21-100:ALLOWED/0x3/0x00120089'
def item(name='a',source=S,target=S):
 return dict(dataset_id=name,source_text=source,target_text=target,protocol='SMB',source_vendor='NetApp',target_vendor='Dell')
class MigrationRiskTests(unittest.TestCase):
 def test_match_not_qualified(self):
  r=assess_migration_acl_risk('migration',[item()])['report'];self.assertEqual(r['overall_status'],'STRUCTURAL_MATCH_NOT_CERTIFIED');self.assertFalse(r['cutover_authorized'])
 def test_blocked_drift(self):
  r=assess_migration_acl_risk('migration',[item(target=S.replace('0x3/','0x2/'))])['report'];self.assertEqual(r['overall_status'],'BLOCKED_POTENTIAL_ACL_LOSS')
 def test_indeterminate(self):
  r=assess_migration_acl_risk('migration',[item(source=S.replace('0x3/','0x100/'),target=S.replace('0x3/','0x100/'))])['report'];self.assertEqual(r['overall_status'],'INDETERMINATE_ACL_TRANSLATION')
 def test_worst_wins(self):
  r=assess_migration_acl_risk('m',[item('ok'),item('bad',target=S.replace('0x3/','0x2/'))])['report'];self.assertEqual(r['overall_status'],'BLOCKED_POTENTIAL_ACL_LOSS');self.assertEqual(r['dataset_count'],2)
 def test_order_independent(self):
  a=[item('z'),item('a')];self.assertEqual(assess_migration_acl_risk('m',a),assess_migration_acl_risk('m',list(reversed(a))))
 def test_duplicate_rejected(self):
  with self.assertRaises(MigrationACLRiskError):assess_migration_acl_risk('m',[item(),item()])
 def test_empty_rejected(self):
  with self.assertRaises(MigrationACLRiskError):assess_migration_acl_risk('m',[])
 def test_bad_migration_rejected(self):
  with self.assertRaises(MigrationACLRiskError):assess_migration_acl_risk('',[item()])
 def test_unknown_vendor_rejected(self):
  d=item();d['target_vendor']='unknown'
  with self.assertRaises(MigrationACLRiskError):assess_migration_acl_risk('m',[d])
 def test_tamper_rejected(self):
  d=[item()];b=assess_migration_acl_risk('m',d);self.assertTrue(verify_migration_acl_risk(b,'m',d));b['report']['cutover_authorized']=True
  with self.assertRaises(MigrationACLRiskError):verify_migration_acl_risk(b,'m',d)
 def test_no_raw_acl_in_report(self):
  r=assess_migration_acl_risk('m',[item()]);self.assertNotIn('OWNER:S-1-5-21-100',str(r))
 def test_extra_field_rejected(self):
  d=item();d['unexpected']=1
  with self.assertRaises(MigrationACLRiskError):assess_migration_acl_risk('m',[d])
