import sqlite3,tempfile,unittest
from pathlib import Path
from registry import Registry
from odmm_scoped_operations import ScopedOperationsView,initialize_grants_schema
from odmm_operations_security import Principal

class ScopedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        p=Path(self.tmp.name);self.db=p/'registry.db';self.grants=p/'grants.db'
        with Registry(self.db) as r:
            self.a=r.create_job('secret-source','secret-target');r.enqueue(self.a,'one',{'mode':'dry_run'})
            self.b=r.create_job('public-source','public-target');r.enqueue(self.b,'two',{'mode':'dry_run'})
        with sqlite3.connect(self.grants) as db:
            initialize_grants_schema(db)
            db.execute('INSERT INTO job_grants VALUES (?,?)',('alice',self.a))
            db.execute('INSERT INTO job_grants VALUES (?,?)',('bob',self.b))
        self.view=ScopedOperationsView(self.db,self.grants)
        self.alice=Principal('alice',frozenset({'viewer'}),True)
        self.bob=Principal('bob',frozenset({'admin'}),True)
    def test_job_filter(self): self.assertEqual([x['id'] for x in self.view.jobs(self.alice)['items']],[self.a])
    def test_other_job_hidden(self):
        with self.assertRaises(LookupError): self.view.operations(self.alice,self.b)
    def test_admin_not_implicit_global(self): self.assertEqual([x['id'] for x in self.view.jobs(self.bob)['items']],[self.b])
    def test_overview_scoped(self):
        o=self.view.overview(self.alice);self.assertEqual(o['jobs'],1);self.assertEqual(o['operations']['PENDING'],1);self.assertIsNone(o['audit_head'])
    def test_no_grants(self):
        p=Principal('nobody',frozenset({'viewer'}),True)
        self.assertEqual(self.view.jobs(p)['items'],[]);self.assertEqual(self.view.overview(p)['jobs'],0)
    def test_unverified_denied(self):
        with self.assertRaises(PermissionError):self.view.jobs(Principal('alice',frozenset({'viewer'}),False))
    def test_invalid_limit(self):
        with self.assertRaises(ValueError):self.view.jobs(self.alice,201)
    def test_missing_grants_fail_closed(self):
        with self.assertRaises(FileNotFoundError):ScopedOperationsView(self.db,Path(self.tmp.name)/'missing')
    def test_read_only(self):
        before=self.db.read_bytes();self.view.jobs(self.alice);self.view.operations(self.alice,self.a);self.assertEqual(before,self.db.read_bytes())
    def test_http_routes_and_identity(self):
        try:
            from fastapi.testclient import TestClient
        except ImportError: self.skipTest('FastAPI test dependencies unavailable')
        from odmm_scoped_app import create_scoped_app
        app=create_scoped_app(registry_path=self.db,grants_path=self.grants,resolve_verified_principal=lambda req:self.alice if req.headers.get('x-test-auth')=='test-only' else None)
        with TestClient(app) as c:
            self.assertEqual(c.get('/api/v1/operations/jobs').status_code,403)
            h={'x-test-auth':'test-only'}
            self.assertEqual(len(c.get('/api/v1/operations/jobs',headers=h).json()['items']),1)
            self.assertEqual(c.get('/api/v1/operations/jobs/'+self.b+'/operations',headers=h).status_code,404)
            self.assertEqual(c.get('/operations',headers=h).status_code,200)
