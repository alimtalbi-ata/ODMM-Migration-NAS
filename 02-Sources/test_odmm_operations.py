import contextlib, io, json, sqlite3, tempfile, unittest
from pathlib import Path
from registry import Registry
from odmm_operations import OperationsView
from odmm_operations_cli import main

class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'reg.sqlite'
        with Registry(self.path) as r:
            self.job=r.create_job('/source','/target')
            self.oid,_=r.enqueue(self.job,'unique',{'mode':'dry_run'})

    def test_overview(self):
        x=OperationsView(self.path).overview()
        self.assertEqual(x['jobs'],1); self.assertEqual(x['operations']['PENDING'],1)
        self.assertTrue(x['read_only']); self.assertEqual(x['audit_head']['seq'],2)

    def test_jobs(self):
        self.assertEqual(OperationsView(self.path).jobs()['items'][0]['id'],self.job)

    def test_operations(self):
        self.assertEqual(OperationsView(self.path).operations(self.job)['items'][0]['id'],self.oid)

    def test_missing_job(self):
        with self.assertRaises(LookupError): OperationsView(self.path).operations('missing')

    def test_sql_injection_safe(self):
        with self.assertRaises(LookupError): OperationsView(self.path).operations("' OR 1=1 --")

    def test_invalid_limits(self):
        for n in (0,-1,201,True,'5'):
            with self.subTest(n=n), self.assertRaises(ValueError): OperationsView(self.path).jobs(n)

    def test_missing_database_not_created(self):
        absent=Path(self.temp.name)/'absent.db'
        with self.assertRaises(FileNotFoundError): OperationsView(absent)
        self.assertFalse(absent.exists())

    def test_cli_contract(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out): self.assertEqual(main(['--db',str(self.path),'overview']),0)
        self.assertEqual(json.loads(out.getvalue()),OperationsView(self.path).overview())

    def test_database_not_mutated(self):
        before=self.path.read_bytes()
        v=OperationsView(self.path); v.overview(); v.jobs(); v.operations(self.job)
        self.assertEqual(before,self.path.read_bytes())

    def test_query_only_connection(self):
        v=OperationsView(self.path)
        with v._connect() as db:
            with self.assertRaises(sqlite3.OperationalError): db.execute('DELETE FROM jobs')
