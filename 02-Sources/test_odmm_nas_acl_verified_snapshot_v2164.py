import tempfile,unittest,sqlite3
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_acl_history_v2149 import AuditHistory
from odmm_nas_acl_recovery_v2151 import RecoverableAnchoredHistory
from odmm_nas_acl_verified_snapshot_v2164 import verified_anchored_snapshot,attach_verified_snapshot
from test_odmm_nas_acl_snapshot_v2163 import KEY,document

class VerifiedSnapshotTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.h=AuditHistory(Path(self.tmp.name)/'audit.sqlite',KEY)
  self.anchor=[None]
  self.a=RecoverableAnchoredHistory(self.h,read_anchor=lambda:self.anchor[0],write_anchor=lambda x:self.anchor.__setitem__(0,x),anchor_key=KEY)
  self.a.bootstrap_empty()
  self.a.record(document());self.a.record(document())
 def test_verified(self):
  p=verified_anchored_snapshot(self.a,limit=1)
  self.assertEqual(p['verified_head_seq'],2)
  self.assertTrue(p['external_anchor_verified'])
  self.assertEqual(p['next_cursor'],1)
 def test_pending_anchor_fail_closed(self):
  self.h.record(document())
  with self.assertRaises(RuntimeError):verified_anchored_snapshot(self.a)
 def test_anchor_tamper_fail_closed(self):
  self.anchor[0]=dict(self.anchor[0],chain_mac='bad')
  with self.assertRaises(RuntimeError):verified_anchored_snapshot(self.a)
 def test_corruption_fail_closed(self):
  with sqlite3.connect(self.h.path) as db:db.execute("UPDATE acl_audit_history SET report='{}' WHERE seq=2")
  with self.assertRaises(RuntimeError):verified_anchored_snapshot(self.a)
 def test_api_auth_and_errors(self):
  app=FastAPI();attach_verified_snapshot(app,authorize=lambda r:r.headers.get('x-key')=='yes',anchored_history=self.a)
  c=TestClient(app)
  self.assertEqual(c.get('/api/v1/operations/nas-acl-audit/verified-snapshot').status_code,403)
  self.assertEqual(c.get('/api/v1/operations/nas-acl-audit/verified-snapshot',headers={'x-key':'yes'}).status_code,200)
  self.assertEqual(c.get('/api/v1/operations/nas-acl-audit/verified-snapshot?limit=101',headers={'x-key':'yes'}).status_code,400)
if __name__=='__main__':unittest.main()
