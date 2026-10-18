import tempfile, unittest
from pathlib import Path
from test_recovery_execution import TestExecution
from executor import RecoveryExecutorRegistry

class TestExecutor(unittest.TestCase):
 def setup_case(self,d):
  r=RecoveryExecutorRegistry(Path(d)/'reg.db')
  job=r.create_job('src','dst'); op,_=r.enqueue(job,'unique',{'file':'a'}); epoch=r.claim(op,'worker',ttl=120)
  import hashlib
  data=b'hello'; intent=r.prepare_write(op,'worker',epoch,str(Path(d)/'target'),0,len(data),hashlib.sha256(data).hexdigest())
  r.begin_chunks(intent,'worker',epoch,chunk_bytes=len(data)); r.write_chunk(intent,'worker',epoch,0,data)
  preview=r.recovery_preview(intent)
  approval,_=r.authorize_recovery(intent,'AUTHORIZE_REPUBLISH','operator',preview['evidence_sha256'])
  return r,approval,epoch
 def test_prepare_idempotent_restart(self):
  with tempfile.TemporaryDirectory() as d:
   r,a,e=self.setup_case(d); x,created=r.prepare_execution(a,'worker',e); self.assertTrue(created)
   self.assertEqual(r.prepare_execution(a,'worker',e),(x,False)); r.db.close()
   r=RecoveryExecutorRegistry(Path(d)/'reg.db'); self.assertEqual(r.inspect_execution(x)['state'],'PREPARED'); r.db.close()
 def test_observation_fenced(self):
  with tempfile.TemporaryDirectory() as d:
   r,a,e=self.setup_case(d); x,_=r.prepare_execution(a,'worker',e)
   with self.assertRaisesRegex(ValueError,'STALE_EXECUTOR'): r.record_observation(x,'worker',e+1,'BLOCKED')
   r.record_observation(x,'worker',e,'REQUIRES_RECONCILIATION')
   self.assertEqual(r.inspect_execution(x)['state'],'RECONCILIATION_REQUIRED'); r.db.close()
 def test_no_external_write(self):
  with tempfile.TemporaryDirectory() as d:
   r,a,e=self.setup_case(d); x,_=r.prepare_execution(a,'worker',e)
   self.assertFalse((Path(d)/'target').exists()); self.assertFalse(r.inspect_execution(x)['automatic_replay_allowed']); r.db.close()
if __name__=='__main__': unittest.main()
