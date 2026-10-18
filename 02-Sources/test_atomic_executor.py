import tempfile, unittest
from pathlib import Path
from executor import RecoveryExecutorRegistry
from test_executor import TestExecutor

class TestAtomicExecutor(unittest.TestCase):
 def setup_case(self,d):
  return TestExecutor().setup_case(d)
 def test_fault_rolls_back_all(self):
  with tempfile.TemporaryDirectory() as d:
   r,a,e=self.setup_case(d)
   with self.assertRaisesRegex(RuntimeError,'INJECTED_CRASH'):
    r.prepare_execution(a,'worker',e,fault_point='BEFORE_COMMIT')
   self.assertEqual(r.db.execute('SELECT state FROM recovery_approvals WHERE approval_id=?',(a,)).fetchone()[0],'APPROVED')
   self.assertEqual(r.db.execute('SELECT COUNT(*) FROM recovery_transitions').fetchone()[0],0)
   self.assertEqual(r.db.execute('SELECT COUNT(*) FROM recovery_executions').fetchone()[0],0)
   r.db.close()
   r=RecoveryExecutorRegistry(Path(d)/'reg.db')
   eid,created=r.prepare_execution(a,'worker',e)
   self.assertTrue(created)
   self.assertEqual(r.inspect_execution(eid)['state'],'PREPARED')
   r.db.close()
 def test_commit_persists_all(self):
  with tempfile.TemporaryDirectory() as d:
   r,a,e=self.setup_case(d)
   eid,_=r.prepare_execution(a,'worker',e)
   self.assertEqual(r.db.execute('SELECT state FROM recovery_approvals WHERE approval_id=?',(a,)).fetchone()[0],'CONSUMED')
   self.assertEqual(r.db.execute('SELECT COUNT(*) FROM recovery_transitions').fetchone()[0],1)
   self.assertEqual(r.db.execute('SELECT COUNT(*) FROM recovery_executions').fetchone()[0],1)
   self.assertEqual(r.prepare_execution(a,'worker',e),(eid,False))
   r.db.close()
 def test_other_owner_cannot_reuse_execution(self):
  with tempfile.TemporaryDirectory() as d:
   r,a,e=self.setup_case(d)
   r.prepare_execution(a,'worker',e)
   with self.assertRaisesRegex(ValueError,'EXECUTION_OWNERSHIP_MISMATCH'):
    r.prepare_execution(a,'attacker',e)
   r.db.close()
