import tempfile,unittest,json,sqlite3
from pathlib import Path
from odmm_campaign_report_v2049 import build_report,export_report
from odmm_campaign_portal_v2049 import CAMPAIGN_PAGE,campaign_csp,attach_campaign_portal

class CampaignTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.db=Path(self.t.name)/'registry.sqlite'
  c=sqlite3.connect(self.db);c.execute('CREATE TABLE fidelity_assessments (id INTEGER PRIMARY KEY,campaign TEXT,timestamp_ns INTEGER,report_json TEXT,sha256 TEXT)')
  r={'status':'UNVERIFIED','mismatches':0,'unverified':3};from native_fidelity_gate_v2043 import _canonical
  import hashlib
  raw=_canonical(r).decode();c.execute('INSERT INTO fidelity_assessments(campaign,timestamp_ns,report_json,sha256) VALUES(?,?,?,?)',('C1',1,raw,hashlib.sha256(raw.encode()).hexdigest()));c.commit();c.close()
 def test_report(self):
  r=build_report(self.db,'C1');self.assertEqual(r['latest_status'],'UNVERIFIED');self.assertEqual(r['total_unverified'],3);self.assertFalse(r['cutover_authorized'])
 def test_empty(self):self.assertEqual(build_report(self.db,'C2')['latest_status'],'NO_EVIDENCE')
 def test_bad_campaign(self):
  with self.assertRaises(ValueError):build_report(self.db,'')
 def test_export(self):
  p=Path(self.t.name)/'out.json';export_report(self.db,'C1',p);self.assertEqual(json.loads(p.read_text())['assessments'],1)
  with self.assertRaises(FileExistsError):export_report(self.db,'C1',p)
 def test_tamper(self):
  c=sqlite3.connect(self.db);c.execute("UPDATE fidelity_assessments SET report_json='{}'");c.commit();c.close()
  with self.assertRaises(ValueError):build_report(self.db,'C1')
 def test_page(self):self.assertIn('campaign-file',CAMPAIGN_PAGE);self.assertIn('Cutover interdit',CAMPAIGN_PAGE)
 def test_csp(self):self.assertEqual(campaign_csp().count("'sha256-"),3)
 def test_auth(self):
  from fastapi import FastAPI
  from fastapi.testclient import TestClient
  app=FastAPI();attach_campaign_portal(app,authorize=lambda r:False)
  self.assertEqual(TestClient(app).get('/qualification/campaign').status_code,403)
 def test_allowed(self):
  from fastapi import FastAPI
  from fastapi.testclient import TestClient
  app=FastAPI();attach_campaign_portal(app,authorize=lambda r:True)
  r=TestClient(app).get('/qualification/campaign');self.assertEqual(r.status_code,200);self.assertIn('Content-Security-Policy',r.headers)
if __name__=='__main__':unittest.main()
