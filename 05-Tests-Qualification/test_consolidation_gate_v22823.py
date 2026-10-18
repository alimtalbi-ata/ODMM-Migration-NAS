import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'09-Tools'))
from consolidation_gate_v22823 import inspect
class GateTests(unittest.TestCase):
 def test_fail_closed(self):
  with tempfile.TemporaryDirectory() as d:
   src=Path(d)/'02-Sources';src.mkdir();(src/'worker_v1.py').write_text('VALUE=1\n');(src/'worker_v2.py').write_text('VALUE=2\n')
   r=inspect(d);self.assertFalse(r['delete_authorized']);self.assertEqual(r['versioned_families'],1)
   self.assertFalse(r['families'][0]['delete_authorized'])
 def test_references(self):
  with tempfile.TemporaryDirectory() as d:
   src=Path(d)/'02-Sources';src.mkdir();(src/'main.py').write_text('import worker_v2\n');(src/'worker_v1.py').write_text('pass\n');(src/'worker_v2.py').write_text('pass\n')
   r=inspect(d);self.assertEqual(r['families'][0]['referenced_members'],['worker_v2'])
 def test_missing_source(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError):inspect(d)
 def test_parse_error_not_delete(self):
  with tempfile.TemporaryDirectory() as d:
   src=Path(d)/'02-Sources';src.mkdir();(src/'broken.py').write_text('def (\n')
   r=inspect(d);self.assertEqual(len(r['parse_errors']),1);self.assertFalse(r['delete_authorized'])
if __name__=='__main__':unittest.main()
