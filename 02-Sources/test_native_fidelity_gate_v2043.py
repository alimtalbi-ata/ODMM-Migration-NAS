import os, sqlite3, tempfile, unittest
from pathlib import Path
from native_fidelity_gate_v2043 import record,history,decision
class GateTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name); self.src=self.root/'src'; self.dst=self.root/'dst'; self.src.mkdir(); self.dst.mkdir(); (self.src/'a').write_bytes(b'abc'); (self.dst/'a').write_bytes(b'abc'); self.db=self.root/'audit.db'
 def test_default_fail_closed_acl(self):
  r=record(self.db,'camp',self.src,self.dst); self.assertIn(r['status'],('UNVERIFIED','MISMATCH')); self.assertFalse(r['cutover_authorized']); self.assertTrue(any(f['field']=='smb_acl' for f in r['report']['findings']))
 def test_digest_history(self):
  r=record(self.db,'camp',self.src,self.dst,required=('content',)); self.assertEqual(len(history(self.db,'camp')),1); self.assertEqual(r['status'],'MATCH'); self.assertFalse(decision(r['report'])['cutover_authorized'])
 def test_mismatch(self):
  (self.dst/'a').write_bytes(b'bad'); r=record(self.db,'camp',self.src,self.dst,required=('content',)); self.assertEqual(r['status'],'MISMATCH')
 def test_tamper(self):
  record(self.db,'camp',self.src,self.dst,required=('content',)); c=sqlite3.connect(self.db); c.execute("UPDATE fidelity_assessments SET report_json='{}'"); c.commit(); c.close(); self.assertRaises(ValueError,history,self.db,'camp')
 def test_missing_history_no_creation(self):
  self.assertRaises(FileNotFoundError,history,self.db,'camp'); self.assertFalse(self.db.exists())
 def test_unknown_requirement(self):
  self.assertRaises(ValueError,record,self.db,'camp',self.src,self.dst,required=('bogus',)); self.assertFalse(self.db.exists())
 def test_separate_campaigns(self):
  record(self.db,'a',self.src,self.dst,required=('content',)); record(self.db,'b',self.src,self.dst,required=('content',)); self.assertEqual(len(history(self.db,'a')),1)
 def test_symlink_registry_rejected(self):
  dest=self.root/'other'; dest.write_text('safe'); self.db.symlink_to(dest); self.assertRaises(ValueError,record,self.db,'camp',self.src,self.dst)
if __name__=='__main__': unittest.main()
