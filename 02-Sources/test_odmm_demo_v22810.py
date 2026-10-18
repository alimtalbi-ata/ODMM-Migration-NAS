import unittest,io,contextlib
from odmm_linux_compact_v22810 import main
from odmm_sample_report_v2289 import sample_rows
from odmm_supervision_v2287 import supervision
class DemoTests(unittest.TestCase):
 def test_demo(self):
  o=io.StringIO()
  with contextlib.redirect_stdout(o): self.assertEqual(main(['--demo-overview']),0)
  self.assertIn('SYNTHETIC DEMONSTRATION',o.getvalue())
  self.assertIn('Bascule autorisée : NON',o.getvalue())
 def test_fixture(self):
  self.assertEqual(supervision(sample_rows())['total'],5)
  self.assertFalse(supervision(sample_rows())['cutover_approved'])
if __name__=='__main__':unittest.main()
