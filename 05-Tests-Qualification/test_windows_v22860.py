import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"02-Sources"))
from odmm_refresh_guard_v22860 import is_current_response,server_limit_notice
class TestRefresh(unittest.TestCase):
 def test_current(self): self.assertTrue(is_current_response(2,2))
 def test_stale(self): self.assertFalse(is_current_response(1,2))
 def test_closed(self): self.assertFalse(is_current_response(2,2,True))
 def test_limit(self): self.assertIn("Limite",server_limit_notice(200))
 def test_not_limit(self): self.assertIn("exhaustivité",server_limit_notice(3))
 def test_invalid(self):
  with self.assertRaises(ValueError): server_limit_notice(-1)
if __name__ == '__main__': unittest.main()
