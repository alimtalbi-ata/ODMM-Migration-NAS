import tempfile, unittest, hashlib
from pathlib import Path
from recovery_plan import RecoveryExecutionRegistry

class TestExecution(unittest.TestCase):
 def setup_case(self,d):
  r=RecoveryExecutionRegistry(Path(d)/'reg.db')
  job=r.create_job('src','dst'); op,_=r.enqueue(job,'unique',{'file':'a'})
  epoch=r.claim(op,'worker',ttl=120)
  data=b'hello world'; target=Path(d)/'target'
  intent=r.prepare_write(op,'worker',epoch,str(target),0,len(data),hashlib.sha256(data).hexdigest())
  r.begin_chunks(intent,'worker',epoch,chunk_bytes=len(data))
  r.write_chunk(intent,'worker',epoch,0,data)
  return r,op,intent,epoch,target
 def test_consume_once_and_persist(self):
  with tempfile.TemporaryDirectory() as d:
   r,op,i,e,target=self.setup_case(d)
   preview=r.recovery_preview(i)
   self.assertEqual(preview['classification']['classification'],'STAGE_COMPLETE_UNPUBLISHED')
   approval,_=r.authorize_recovery(i,'AUTHORIZE_REPUBLISH','operator',preview['evidence_sha256'])
   self.assertTrue(r.consume_approval(approval,'worker',e))
   self.assertFalse(r.consume_approval(approval,'worker',e))
   self.assertFalse(target.exists()) # consumption never publishes
   r.db.close(); r=RecoveryExecutionRegistry(Path(d)/'reg.db')
   self.assertEqual(r.db.execute('SELECT COUNT(*) FROM recovery_transitions').fetchone()[0],1)
   r.db.close()
 def test_changed_evidence_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   r,op,i,e,target=self.setup_case(d)
   preview=r.recovery_preview(i)
   approval,_=r.authorize_recovery(i,'AUTHORIZE_REPUBLISH','operator',preview['evidence_sha256'])
   target.write_bytes(b'conflict')
   with self.assertRaisesRegex(ValueError,'EVIDENCE_CHANGED'): r.consume_approval(approval,'worker',e)
   self.assertEqual(r.db.execute('SELECT state FROM recovery_approvals').fetchone()[0],'APPROVED')
   r.db.close()
 def test_stale_epoch_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   r,op,i,e,target=self.setup_case(d)
   preview=r.recovery_preview(i)
   approval,_=r.authorize_recovery(i,'AUTHORIZE_REPUBLISH','operator',preview['evidence_sha256'])
   with self.assertRaisesRegex(ValueError,'STALE_OR_MISSING_LEASE'): r.consume_approval(approval,'worker',e+1)
   self.assertEqual(r.db.execute('SELECT COUNT(*) FROM recovery_transitions').fetchone()[0],0)
   r.db.close()
if __name__=='__main__': unittest.main()
