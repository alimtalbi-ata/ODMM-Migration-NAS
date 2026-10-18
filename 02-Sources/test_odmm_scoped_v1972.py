import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from registry import Registry
from odmm_scoped_operations import initialize_grants_schema
from odmm_operations_security import Principal
from odmm_scoped_cli import run,main
from odmm_production_entrypoint import create_production_app

class IntegrationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  root=Path(self.tmp.name);self.db=root/'r.db';self.grants=root/'g.db'
  with Registry(self.db) as r:
   self.a=r.create_job('private','target');r.enqueue(self.a,'op',{'mode':'dry_run'})
   self.b=r.create_job('hidden','target');r.enqueue(self.b,'op',{'mode':'dry_run'})
  with sqlite3.connect(self.grants) as db:
   initialize_grants_schema(db);db.execute('INSERT INTO job_grants VALUES (?,?)',('alice',self.a))
  self.alice=Principal('alice',frozenset({'viewer'}),True)
 def args(self,*cmd): return ['--db',str(self.db),'--grants-db',str(self.grants),*cmd]
 def test_cli_missing_identity(self):
  with self.assertRaises(PermissionError):run(self.args('jobs'))
 def test_cli_unverified(self):
  with self.assertRaises(PermissionError):run(self.args('jobs'),resolve_verified_principal=lambda:Principal('alice',frozenset({'viewer'}),False))
 def test_cli_only_authorized(self):
  out=[];run(self.args('jobs'),resolve_verified_principal=lambda:self.alice,output=out.append)
  self.assertIn(self.a,out[0]);self.assertNotIn(self.b,out[0]);self.assertNotIn('hidden',out[0])
 def test_cli_no_cross_tenant_operations(self):
  with self.assertRaises(LookupError):run(self.args('operations','--job-id',self.b),resolve_verified_principal=lambda:self.alice,output=lambda _:None)
 def test_cli_overview_scoped(self):
  out=[];run(self.args('overview'),resolve_verified_principal=lambda:self.alice,output=out.append)
  import json
  self.assertEqual(json.loads(out[0])['jobs'],1)
 def test_cli_no_unsafe_subject_flag(self):
  with self.assertRaises(SystemExit):run(self.args('jobs','--subject','admin'),resolve_verified_principal=lambda:self.alice)
 def test_cli_standalone_disabled(self):
  with self.assertRaises(SystemExit):main()
 def test_production_requires_resolver(self):
  with self.assertRaises(ValueError):create_production_app(registry_path=self.db,grants_path=self.grants,resolve_verified_principal=None)
 def test_production_routes_and_http(self):
  try:from fastapi.testclient import TestClient
  except ImportError:self.skipTest('FastAPI test client unavailable')
  app=create_production_app(registry_path=self.db,grants_path=self.grants,resolve_verified_principal=lambda req:self.alice if req.headers.get('x-integration-test')=='yes' else None)
  with TestClient(app) as client:
   self.assertEqual(client.get('/api/v1/operations/jobs').status_code,403)
   h={'x-integration-test':'yes'}
   data=client.get('/api/v1/operations/jobs',headers=h).json()
   self.assertEqual(len(data['items']),1)
   self.assertEqual(client.get('/api/v1/operations/jobs/'+self.b+'/operations',headers=h).status_code,404)
   self.assertEqual(client.get('/operations',headers=h).status_code,200)
   self.assertEqual(client.get('/api/v1/legacy/jobs',headers=h).status_code,404)
 def test_registry_unmodified(self):
  before=self.db.read_bytes();run(self.args('jobs'),resolve_verified_principal=lambda:self.alice,output=lambda _:None);self.assertEqual(before,self.db.read_bytes())
