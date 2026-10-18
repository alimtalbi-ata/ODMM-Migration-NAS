import hashlib, tempfile, unittest
from pathlib import Path
from staging import StagedRegistry
class StagingTests(unittest.TestCase):
 def test_publish_and_audit(self):
  with tempfile.TemporaryDirectory() as d:
   r=StagedRegistry(Path(d)/'db.sqlite'); job=r.create_job('s','t'); oid,_=r.enqueue(job,'x',{'x':1}); epoch=r.claim(oid,'worker',60)
   payload=b'ODMM-V176.4'; target=Path(d)/'target'
   iid=r.prepare_write(oid,'worker',epoch,target,0,len(payload),hashlib.sha256(payload).hexdigest())
   self.assertTrue(r.stage_local(iid,'worker',epoch,payload)); self.assertEqual(target.read_bytes(),payload)
   self.assertEqual(r.db.execute('select state from write_intents where intent_id=?',(iid,)).fetchone()['state'],'VERIFIED')
 def test_no_unsafe_replay(self):
  with tempfile.TemporaryDirectory() as d:
   r=StagedRegistry(Path(d)/'db.sqlite'); job=r.create_job('s','t'); oid,_=r.enqueue(job,'x',{'x':1}); epoch=r.claim(oid,'worker',60)
   payload=b'data'; target=Path(d)/'target'; target.write_bytes(b'old')
   iid=r.prepare_write(oid,'worker',epoch,target,0,len(payload),hashlib.sha256(payload).hexdigest())
   with self.assertRaises(FileExistsError): r.stage_local(iid,'worker',epoch,payload)
   self.assertEqual(target.read_bytes(),b'old')
   self.assertFalse(r.stage_local(iid,'stale',epoch,payload))
 def test_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   r=StagedRegistry(Path(d)/'db.sqlite'); job=r.create_job('s','t'); oid,_=r.enqueue(job,'x',{'x':1}); epoch=r.claim(oid,'worker',60)
   target=Path(d)/'target'; target.symlink_to(Path(d)/'other'); data=b'a'
   iid=r.prepare_write(oid,'worker',epoch,target,0,1,hashlib.sha256(data).hexdigest())
   with self.assertRaises(ValueError): r.stage_local(iid,'worker',epoch,data)
if __name__=='__main__': unittest.main()
