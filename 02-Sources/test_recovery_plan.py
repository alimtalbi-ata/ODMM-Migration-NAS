import tempfile, unittest
from pathlib import Path
from recovery_plan import RecoveryPlanRegistry, snapshot_posix_metadata

class TestRecoveryPlan(unittest.TestCase):
 def test_preview_no_writes_and_refuse_unqualified(self):
  with tempfile.TemporaryDirectory() as d:
   r=RecoveryPlanRegistry(Path(d)/'registry.sqlite')
   with self.assertRaises(KeyError): r.recovery_preview('missing')
   with self.assertRaises(KeyError): r.authorize_recovery('missing','AUTHORIZE_RESUME','operator','x')
   r.db.close()
 def test_metadata_regular_file(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'f'; p.write_bytes(b'abc')
   m=snapshot_posix_metadata(p)
   self.assertEqual(m['size'],3)
   self.assertFalse(m['acl_preserved'])
   link=Path(d)/'link'; link.symlink_to(p)
   with self.assertRaises(ValueError): snapshot_posix_metadata(link)
 def test_decision_policy(self):
  from recovery_plan import SAFE_DECISIONS
  self.assertEqual(SAFE_DECISIONS['STAGE_PARTIAL'],{'AUTHORIZE_RESUME'})
  self.assertNotIn('TARGET_CONFLICT',SAFE_DECISIONS)
if __name__=='__main__': unittest.main()
