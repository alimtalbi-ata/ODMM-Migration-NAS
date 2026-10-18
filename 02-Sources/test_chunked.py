import hashlib,tempfile,unittest
from pathlib import Path
from chunked import ChunkedRegistry
class ChunkTests(unittest.TestCase):
 def setup_session(self,d):
  r=ChunkedRegistry(Path(d)/'db'); job=r.create_job('source','target'); oid,_=r.enqueue(job,'one',{'x':1}); ep=r.claim(oid,'w',60)
  payload=b'abcdefghij'; target=Path(d)/'out'; iid=r.prepare_write(oid,'w',ep,target,0,len(payload),hashlib.sha256(payload).hexdigest()); self.assertTrue(r.begin_chunks(iid,'w',ep,4)); return r,oid,ep,iid,target,payload
 def test_resume_and_publish(self):
  with tempfile.TemporaryDirectory() as d:
   r,oid,ep,iid,target,payload=self.setup_session(d)
   self.assertTrue(r.write_chunk(iid,'w',ep,0,payload[:4])); r.db.close()
   r=ChunkedRegistry(Path(d)/'db'); self.assertEqual(r.inspect_chunks(iid)['missing_offsets'],[4,8])
   self.assertTrue(r.write_chunk(iid,'w',ep,4,payload[4:8])); self.assertTrue(r.write_chunk(iid,'w',ep,8,payload[8:])); self.assertTrue(r.publish_chunks(iid,'w',ep)); self.assertEqual(target.read_bytes(),payload)
 def test_duplicate_and_conflict(self):
  with tempfile.TemporaryDirectory() as d:
   r,oid,ep,iid,target,payload=self.setup_session(d)
   self.assertTrue(r.write_chunk(iid,'w',ep,0,b'abcd')); self.assertTrue(r.write_chunk(iid,'w',ep,0,b'abcd'))
   with self.assertRaises(ValueError): r.write_chunk(iid,'w',ep,0,b'xxxx')
 def test_fencing(self):
  with tempfile.TemporaryDirectory() as d:
   r,oid,ep,iid,target,payload=self.setup_session(d)
   self.assertFalse(r.write_chunk(iid,'old',ep,0,b'abcd'))
   self.assertFalse(r.publish_chunks(iid,'old',ep))
 def test_corruption(self):
  with tempfile.TemporaryDirectory() as d:
   r,oid,ep,iid,target,payload=self.setup_session(d)
   for offset in (0,4,8): r.write_chunk(iid,'w',ep,offset,payload[offset:offset+4])
   stage=Path(r.db.execute('SELECT stage_path FROM chunk_sessions WHERE intent_id=?',(iid,)).fetchone()[0]); stage.write_bytes(b'X'+stage.read_bytes()[1:])
   self.assertFalse(r.inspect_chunks(iid)['complete'])
   with self.assertRaises(ValueError): r.publish_chunks(iid,'w',ep)
if __name__=='__main__':unittest.main()
