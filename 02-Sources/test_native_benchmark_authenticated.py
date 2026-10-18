import json
import tempfile
import unittest
from pathlib import Path
from native_benchmark_authenticated import append_authenticated,read_authenticated,rotate_authenticated

class AuthHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'authenticated.jsonl'
        self.keys={'k1':b'A'*32,'k2':b'B'*32}
        self.report={'schema':'odmm.audit.mixed_benchmark.v1','status':'PASS','error_count':0,'secret':'HIDDEN','cutover_authorized':False,'source_read_only':True,'isolated_copy':True}
    def add(self,**kw):return append_authenticated(self.path,self.report,keys=self.keys,**kw)
    def read(self,**kw):return read_authenticated(self.path,keys=self.keys,**kw)
    def test_empty(self):self.assertEqual(self.read()['status'],'EMPTY')
    def test_initial_append_and_redaction(self):
        self.add(key_id='k1');self.assertEqual(self.read()['total'],1)
        self.assertNotIn('HIDDEN',self.path.read_text())
    def test_rotation(self):
        self.add(key_id='k1');rotate_authenticated(self.path,keys=self.keys,new_key_id='k2');self.add()
        self.assertEqual(self.read()['active_key_id'],'k2');self.assertEqual(self.read()['total'],2)
    def test_old_key_required(self):
        self.add(key_id='k1');rotate_authenticated(self.path,keys=self.keys,new_key_id='k2')
        with self.assertRaises(ValueError):read_authenticated(self.path,keys={'k2':self.keys['k2']})
    def test_wrong_key(self):
        self.add(key_id='k1')
        with self.assertRaises(ValueError):read_authenticated(self.path,keys={'k1':b'Z'*32})
    def test_tamper(self):
        self.add(key_id='k1');self.path.write_text(self.path.read_text().replace('PASS','FAIL'))
        with self.assertRaises(ValueError):self.read()
        with self.assertRaises(ValueError):self.add()
    def test_trusted_head(self):
        self.add(key_id='k1');head=self.read()['head_sha256'];self.add()
        with self.assertRaises(ValueError):self.read(trusted_head=head)
    def test_rotation_requires_explicit(self):
        self.add(key_id='k1')
        with self.assertRaises(ValueError):self.add(key_id='k2')
    def test_rotation_reject_missing(self):
        with self.assertRaises(FileNotFoundError):rotate_authenticated(self.path,keys=self.keys,new_key_id='k2')
    def test_no_cutover(self):
        self.add(key_id='k1');self.assertFalse(self.read()['cutover_authorized'])
