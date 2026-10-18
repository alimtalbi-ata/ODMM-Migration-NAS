"""ODMM portal OIDC read-only integration. Author: Abdelhalim Talbi."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_operations_portal import attach_operations_portal
from odmm_oidc_health_history_v1995 import ingest
class PortalOIDCTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'history.sqlite'
        self.app=FastAPI()
        attach_operations_portal(self.app,authorize=lambda r:r.headers.get('x-allow')=='yes',oidc_history_db=self.db)
        self.client=TestClient(self.app)
    def test_unauthorized_endpoint_rejected(self):
        self.assertEqual(self.client.get('/api/v1/operations/oidc-health').status_code,403)
    def test_missing_database_is_503(self):
        self.assertEqual(self.client.get('/api/v1/operations/oidc-health',headers={'x-allow':'yes'}).status_code,503)
    def test_snapshot_from_history(self):
        report=Path(self.tmp.name)/'report.json'
        report.write_text(json.dumps({'checks':[{'state':'AVAILABLE','discovery_jwks_ok':True,'latency_ms':12.5}]}))
        ingest(self.db,report)
        res=self.client.get('/api/v1/operations/oidc-health',headers={'x-allow':'yes'})
        self.assertEqual(res.status_code,200)
        self.assertEqual(res.json()['observations'][0]['state'],'AVAILABLE')
        self.assertEqual(res.json()['migration_engine_status'],'NOT_MEASURED')
        self.assertEqual(res.headers['cache-control'],'no-store')
    def test_html_contains_oidc_section_and_safe_text(self):
        res=self.client.get('/operations',headers={'x-allow':'yes'})
        self.assertEqual(res.status_code,200)
        self.assertIn('oidc-panel',res.text)
        self.assertIn('Content-Security-Policy',res.headers)
        self.assertIn('textContent',res.text)
    def test_unauthorized_ui_rejected(self):
        self.assertEqual(self.client.get('/operations').status_code,403)
