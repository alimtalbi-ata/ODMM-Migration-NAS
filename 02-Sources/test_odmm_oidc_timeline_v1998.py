"""OIDC event timeline read-only integration. Author Abdelhalim Talbi."""
import tempfile,unittest
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_operations_portal import attach_operations_portal
from odmm_oidc_health_history_v1995 import ingest
from odmm_oidc_alerts_v1997 import reconcile
import json
class TimelineTests(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
  self.db=Path(tmp.name)/'oidc.sqlite'; self.app=FastAPI()
  attach_operations_portal(self.app,authorize=lambda r:r.headers.get('x-allow')=='yes',oidc_history_db=self.db)
  self.client=TestClient(self.app)
  self.h={'x-allow':'yes'}
 def seed(self):
  f=self.db.parent/'observations.json'
  f.write_text(json.dumps({'checks':[{'state':s,'latency_ms':10,'discovery_jwks_ok':True} for s in ['AVAILABLE','DEGRADED','UNAVAILABLE','AVAILABLE']]}))
  ingest(self.db,f);reconcile(self.db)
 def test_unauthorized(self):
  self.assertEqual(self.client.get('/api/v1/operations/oidc-events').status_code,403)
 def test_missing_history(self):
  self.assertEqual(self.client.get('/api/v1/operations/oidc-events',headers=self.h).status_code,503)
 def test_transitions(self):
  self.seed();r=self.client.get('/api/v1/operations/oidc-events',headers=self.h)
  self.assertEqual(r.status_code,200)
  self.assertEqual([x['event'] for x in reversed(r.json()['events'])],['OIDC_DEGRADED','OIDC_OUTAGE','OIDC_RECOVERED'])
  self.assertEqual(r.json()['migration_engine_status'],'NOT_MEASURED')
 def test_limit_and_bounds(self):
  self.seed()
  self.assertEqual(len(self.client.get('/api/v1/operations/oidc-events?limit=1',headers=self.h).json()['events']),1)
  self.assertEqual(self.client.get('/api/v1/operations/oidc-events?limit=0',headers=self.h).status_code,422)
  self.assertEqual(self.client.get('/api/v1/operations/oidc-events?limit=1001',headers=self.h).status_code,422)
 def test_page_safe_rendering(self):
  r=self.client.get('/operations',headers=self.h)
  self.assertEqual(r.status_code,200)
  self.assertIn('oidc-timeline',r.text)
  self.assertIn('oidc-filter',r.text)
  self.assertIn('textContent',r.text)
  self.assertIn('Content-Security-Policy',r.headers)
 def test_no_store(self):
  self.seed();r=self.client.get('/api/v1/operations/oidc-events',headers=self.h)
  self.assertEqual(r.headers['cache-control'],'no-store')
