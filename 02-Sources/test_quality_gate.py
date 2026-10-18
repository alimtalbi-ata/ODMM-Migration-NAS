import tempfile
import unittest
from pathlib import Path
from quality_gate import run_gate

class QualityGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def write(self,name,body): (self.root/name).write_text(body,encoding='utf-8')
    def test_pass(self):
        self.write('test_good.py','import unittest\nclass T(unittest.TestCase):\n def test_ok(self): self.assertTrue(True)\n')
        r=run_gate(self.root)
        self.assertEqual((r['status'],r['passed'],r['modules']),('PASS',1,1))
        self.assertFalse(r['production_qualified'])
    def test_failure(self):
        self.write('test_bad.py','import unittest\nclass T(unittest.TestCase):\n def test_bad(self): self.fail("bad")\n')
        r=run_gate(self.root)
        self.assertEqual((r['status'],r['failed']),('FAIL',1))
    def test_timeout(self):
        self.write('test_slow.py','import time\ntime.sleep(5)\n')
        r=run_gate(self.root,timeout=1)
        self.assertEqual(r['timed_out'],1)
    def test_report_no_overwrite(self):
        self.write('test_good.py','import unittest\nclass T(unittest.TestCase):\n def test_ok(self): pass\n')
        target=self.root/'report.json'
        run_gate(self.root,report=target)
        with self.assertRaises(FileExistsError): run_gate(self.root,report=target)
    def test_bad_pattern(self):
        with self.assertRaises(ValueError):run_gate(self.root,pattern='../test_*.py')
    def test_bad_timeout(self):
        with self.assertRaises(ValueError):run_gate(self.root,timeout=0)
    def test_empty_fail_closed(self):
        self.assertEqual(run_gate(self.root)['status'],'FAIL')
    def test_multiple(self):
        for i in range(3):self.write(f'test_{i}.py','import unittest\nclass T(unittest.TestCase):\n def test_ok(self): pass\n')
        self.assertEqual(run_gate(self.root)['passed'],3)
