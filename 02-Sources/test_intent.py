import hashlib, tempfile, unittest
from pathlib import Path
from intent import IntentRegistry
from registry import verify
class Tests(unittest.TestCase):
 def test_intent_recovery(self):
  with tempfile.TemporaryDirectory() as d:
   r=IntentRegistry(Path(d)/'reg.sqlite'); j=r.create_job('src','dst'); oid,_=r.enqueue(j,'file1',{'name':'file1'}); e=r.claim(oid,'worker',60)
   data=b'ODMM-safe-block'; target=Path(d)/'target'; target.write_bytes(data)
   h=hashlib.sha256(data).hexdigest(); iid=r.prepare_write(oid,'worker',e,target,0,len(data),h)
   self.assertEqual(iid,r.prepare_write(oid,'worker',e,target,0,len(data),h))
   self.assertTrue(r.inspect_intent(iid)['verified']); self.assertTrue(r.acknowledge_write(iid,'worker',e))
   self.assertFalse(r.acknowledge_write(iid,'worker',e)); self.assertTrue(r.complete(oid,'worker',e))
   export=Path(d)/'audit.jsonl'; r.export_snapshot(export); self.assertTrue(verify(export))
 def test_missing_and_conflict(self):
  with tempfile.TemporaryDirectory() as d:
   r=IntentRegistry(Path(d)/'r.db'); j=r.create_job('a','b'); oid,_=r.enqueue(j,'k',{'x':1}); e=r.claim(oid,'w',60)
   h=hashlib.sha256(b'abc').hexdigest(); iid=r.prepare_write(oid,'w',e,Path(d)/'missing',0,3,h)
   self.assertFalse(r.inspect_intent(iid)['verified']); self.assertFalse(r.acknowledge_write(iid,'w',e))
   with self.assertRaises(ValueError): r.prepare_write(oid,'w',e,Path(d)/'other',0,3,h)
if __name__=='__main__': unittest.main()
