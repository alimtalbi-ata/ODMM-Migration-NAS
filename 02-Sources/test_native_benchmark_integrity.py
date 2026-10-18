import json
import tempfile
import unittest
from pathlib import Path
from native_benchmark_integrity import append_verified,read_verified

class VerifiedHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'history.chain.jsonl'
        self.report={'schema':'odmm.audit.mixed_benchmark.v1','status':'PASS','cutover_authorized':False,'source_read_only':True,'isolated_copy':True,'reader_operations':12,'writer_attempts':5,'writer_busy_conflict_rate':0,'elapsed_s':1.2,'error_count':0,'secret':'NEVER_STORE'}
    def test_empty(self):self.assertEqual(read_verified(self.path)['status'],'EMPTY')
    def test_append(self):
        append_verified(self.path,self.report);append_verified(self.path,self.report)
        self.assertEqual(read_verified(self.path)['total'],2)
        self.assertNotIn('NEVER_STORE',self.path.read_text())
    def test_tamper(self):
        append_verified(self.path,self.report)
        data=self.path.read_text().replace('"reader_operations":12','"reader_operations":13')
        self.path.write_text(data)
        with self.assertRaises(ValueError):read_verified(self.path)
        with self.assertRaises(ValueError):append_verified(self.path,self.report)
    def test_truncation(self):
        append_verified(self.path,self.report)
        self.path.write_bytes(self.path.read_bytes()[:-1])
        with self.assertRaises(ValueError):read_verified(self.path)
    def test_missing_record(self):
        for _ in range(3):append_verified(self.path,self.report)
        lines=self.path.read_text().splitlines()
        self.path.write_text('\n'.join([lines[0],lines[2]])+'\n')
        with self.assertRaises(ValueError):read_verified(self.path)
    def test_reordering(self):
        for _ in range(2):append_verified(self.path,self.report)
        lines=self.path.read_text().splitlines()
        self.path.write_text('\n'.join(reversed(lines))+'\n')
        with self.assertRaises(ValueError):read_verified(self.path)
    def test_limit_still_verifies_all(self):
        for _ in range(3):append_verified(self.path,self.report)
        self.assertEqual(len(read_verified(self.path,limit=1)['records']),1)
        lines=self.path.read_text().splitlines();lines[0]=lines[0].replace('"reader_operations":12','"reader_operations":99')
        self.path.write_text('\n'.join(lines)+'\n')
        with self.assertRaises(ValueError):read_verified(self.path,limit=1)
    def test_reject_symlink(self):
        real=Path(self.temp.name)/'real';real.write_text('')
        self.path.symlink_to(real)
        with self.assertRaises(OSError):append_verified(self.path,self.report)
    def test_no_cutover(self):
        append_verified(self.path,self.report)
        self.assertFalse(read_verified(self.path)['cutover_authorized'])
