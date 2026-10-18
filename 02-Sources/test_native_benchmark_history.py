import json
import tempfile
import unittest
from pathlib import Path
from native_benchmark_history import append_history, read_history, cockpit_html

class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'history.jsonl'
        self.report={'schema':'odmm.audit.mixed_benchmark.v1','status':'PASS','cutover_authorized':False,'source_read_only':True,'isolated_copy':True,'reader_operations':12,'writer_attempts':5,'writer_busy_conflict_rate':0.0,'elapsed_s':1.2,'error_count':0,'secret':'DO_NOT_STORE'}
    def test_append_and_read(self):
        append_history(self.path,self.report)
        self.assertEqual(read_history(self.path)[0]['reader_operations'],12)
    def test_no_secrets(self):
        append_history(self.path,self.report)
        self.assertNotIn('DO_NOT_STORE',self.path.read_text())
    def test_multiple_entries(self):
        for _ in range(3): append_history(self.path,self.report)
        self.assertEqual(len(read_history(self.path,limit=2)),2)
    def test_refuse_cutover(self):
        self.report['cutover_authorized']=True
        with self.assertRaises(ValueError): append_history(self.path,self.report)
    def test_refuse_unisolated(self):
        self.report['isolated_copy']=False
        with self.assertRaises(ValueError): append_history(self.path,self.report)
    def test_truncated_history(self):
        self.path.write_text('bad')
        with self.assertRaises(ValueError): append_history(self.path,self.report)
        with self.assertRaises(ValueError): read_history(self.path)
    def test_symlink(self):
        actual=Path(self.tmp.name)/'actual';actual.write_text('')
        self.path.symlink_to(actual)
        with self.assertRaises(OSError): append_history(self.path,self.report)
    def test_dashboard_escape(self):
        report=dict(self.report,status='FAIL')
        page=cockpit_html([report]);self.assertIn('FAIL',page);self.assertIn('aucun cutover',page)
    def test_schema(self):
        self.report['schema']='other'
        with self.assertRaises(ValueError):append_history(self.path,self.report)
if __name__=='__main__': unittest.main()
