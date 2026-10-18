import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import native_benchmark_authenticated as auth

class AtomicBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'history.jsonl'
        self.keys={'a':b'A'*32,'b':b'B'*32}
        self.report={'schema':'odmm.audit.mixed_benchmark.v1','status':'PASS','error_count':0,'source_read_only':True,'isolated_copy':True,'cutover_authorized':False}
    def append(self):return auth.append_authenticated(self.path,self.report,keys=self.keys,key_id='a')
    def test_bootstrap_two_records_single_batch(self):
        with patch.object(auth,'_append_batch',wraps=auth._append_batch) as batch:
            self.append()
            self.assertEqual(batch.call_count,1)
            self.assertEqual(len(batch.call_args.args[1]),2)
        self.assertEqual(auth.read_authenticated(self.path,keys=self.keys)['total'],1)
    def test_prewrite_failure_does_not_create_orphan_start(self):
        with patch.object(auth.os,'write',side_effect=OSError('injected failure')):
            with self.assertRaises(OSError):self.append()
        self.assertEqual(self.path.read_bytes(),b'')
        self.append()
        self.assertEqual(auth.read_authenticated(self.path,keys=self.keys)['total'],1)
    def test_partial_bootstrap_fails_closed(self):
        original=auth.os.write
        def partial(fd,data):
            original(fd,data[:23]);raise OSError('simulated crash after partial write')
        with patch.object(auth.os,'write',side_effect=partial):
            with self.assertRaises(OSError):self.append()
        with self.assertRaises(ValueError):auth.read_authenticated(self.path,keys=self.keys)
        with self.assertRaises(ValueError):self.append()
    def test_valid_start_only_can_be_continued(self):
        self.append()
        rows=self.path.read_bytes().splitlines(keepends=True)
        self.path.write_bytes(rows[0])
        self.assertEqual(auth.read_authenticated(self.path,keys=self.keys)['total'],0)
        self.append()
        self.assertEqual(auth.read_authenticated(self.path,keys=self.keys)['total'],1)
    def test_subsequent_append_still_one_record(self):
        self.append()
        with patch.object(auth,'_append_batch',wraps=auth._append_batch) as batch:
            auth.append_authenticated(self.path,self.report,keys=self.keys)
            self.assertEqual(len(batch.call_args.args[1]),1)
        self.assertEqual(auth.read_authenticated(self.path,keys=self.keys)['total'],2)
