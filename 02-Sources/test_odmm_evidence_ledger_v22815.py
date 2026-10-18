import json,sqlite3,tempfile,unittest
from pathlib import Path
from odmm_market_readiness_v22812 import REQUIRED
from odmm_evidence_ledger_v22814 import record
from odmm_evidence_ledger_v22815 import inspect,anchor,check_anchor
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.db=Path(self.tmp.name)/"audit.sqlite"
  self.e={k:{"status":"PASS","evidence_id":k,"job_id":"J1"} for k in REQUIRED}
 def tearDown(self): self.tmp.cleanup()
 def test_missing_does_not_create(self):
  with self.assertRaises(FileNotFoundError): inspect(self.db)
  self.assertFalse(self.db.exists())
 def test_valid(self):
  record(self.db,"J1",self.e); self.assertTrue(inspect(self.db)["valid"])
 def test_anchor(self):
  record(self.db,"J1",self.e); self.assertTrue(check_anchor(self.db,anchor(self.db))["valid"])
 def test_anchor_mismatch_after_append(self):
  record(self.db,"J1",self.e); a=anchor(self.db)
  record(self.db,"J2",self.e); self.assertFalse(check_anchor(self.db,a)["valid"])
 def test_sequence_gap(self):
  record(self.db,"J1",self.e); record(self.db,"J2",self.e)
  with sqlite3.connect(self.db) as c: c.execute("DELETE FROM audit_events WHERE sequence=1")
  self.assertFalse(inspect(self.db)["valid"])
 def test_tamper(self):
  record(self.db,"J1",self.e)
  with sqlite3.connect(self.db) as c: c.execute("UPDATE audit_events SET result_json='{}'")
  self.assertFalse(inspect(self.db)["valid"])
 def test_wrong_anchor(self):
  record(self.db,"J1",self.e); self.assertFalse(check_anchor(self.db,{} )["valid"])
if __name__=="__main__":unittest.main()
