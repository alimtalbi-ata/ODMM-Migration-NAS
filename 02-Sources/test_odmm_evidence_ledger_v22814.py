import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from odmm_market_readiness_v22812 import REQUIRED
from odmm_evidence_ledger_v22814 import record,verify

class LedgerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory()
  self.db=Path(self.tmp.name)/"audit.sqlite"
  self.e={k:{"status":"PASS","evidence_id":k,"job_id":"J-1"} for k in REQUIRED}
 def tearDown(self): self.tmp.cleanup()
 def test_append_and_verify(self):
  a=record(self.db,"J-1",self.e)
  self.assertFalse(a["duplicate"])
  self.assertFalse(a["result"]["cutover_authorized"])
  self.assertTrue(verify(self.db)["valid"])
 def test_idempotent(self):
  record(self.db,"J-1",self.e)
  self.assertTrue(record(self.db,"J-1",self.e)["duplicate"])
  self.assertEqual(verify(self.db)["events"],1)
 def test_chain(self):
  record(self.db,"J-1",self.e)
  changed=dict(self.e); changed["inventory"]={"status":"FAIL","evidence_id":"inventory","job_id":"J-1"}
  record(self.db,"J-1",changed)
  self.assertEqual(verify(self.db)["events"],2)
 def test_tamper_detected(self):
  record(self.db,"J-1",self.e)
  with sqlite3.connect(self.db) as db: db.execute("UPDATE audit_events SET result_json='{}' WHERE sequence=1")
  self.assertFalse(verify(self.db)["valid"])
 def test_job_mismatch(self):
  r=record(self.db,"J-2",self.e)
  self.assertTrue(r["result"]["anomalies"])
 def test_reject_invalid_id(self):
  with self.assertRaises(ValueError): record(self.db,"",self.e)
if __name__=="__main__": unittest.main()
