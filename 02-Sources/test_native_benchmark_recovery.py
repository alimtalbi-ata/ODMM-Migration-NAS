import tempfile
import unittest
from pathlib import Path
from native_benchmark_authenticated import append_authenticated, rotate_authenticated
from native_benchmark_recovery import diagnose_authenticated

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'history.jsonl'
        self.keys={'one':b'1'*32,'two':b'2'*32}
        self.report={'schema':'odmm.audit.mixed_benchmark.v1','status':'PASS','error_count':0,'cutover_authorized':False,'source_read_only':True,'isolated_copy':True}
    def status(self,**kw):return diagnose_authenticated(self.path,keys=self.keys,**kw)
    def add(self):return append_authenticated(self.path,self.report,keys=self.keys,key_id='one')
    def test_missing(self):
        r=self.status();self.assertEqual(r['status'],'EMPTY');self.assertFalse(self.path.exists())
    def test_valid(self):
        self.add();r=self.status();self.assertEqual(r['status'],'VERIFIED');self.assertEqual(r['records'],2)
    def test_incomplete_tail(self):
        self.add();self.path.write_bytes(self.path.read_bytes()+b'{"unfinished":')
        before=self.path.read_bytes();r=self.status();self.assertEqual(r['reason'],'INCOMPLETE_TAIL');self.assertEqual(before,self.path.read_bytes())
    def test_tamper(self):
        self.add();self.path.write_bytes(self.path.read_bytes().replace(b'PASS',b'FAIL'))
        self.assertEqual(self.status()['reason'],'INTEGRITY_OR_KEY_FAILURE')
    def test_missing_key_no_secret(self):
        self.add();r=diagnose_authenticated(self.path,keys={});self.assertEqual(r['status'],'BLOCKED');self.assertNotIn('key',str(r).lower().replace('key_failure',''))
    def test_anchor_mismatch(self):
        self.add();self.assertEqual(self.status(trusted_head='f'*64)['status'],'BLOCKED')
    def test_rotation(self):
        self.add();rotate_authenticated(self.path,keys=self.keys,new_key_id='two')
        self.assertEqual(self.status()['active_key_id'],'two')
    def test_no_automatic_actions(self):
        self.add();r=self.status();self.assertFalse(r['automatic_repair']);self.assertFalse(r['cutover_authorized']);self.assertTrue(r['requires_human_approval'])
    def test_empty_existing(self):
        self.path.touch();self.assertEqual(self.status()['reason'],'JOURNAL_EMPTY')
