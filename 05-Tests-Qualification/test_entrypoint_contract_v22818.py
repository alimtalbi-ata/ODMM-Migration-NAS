import tempfile,unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'02-Sources'))
from odmm_entrypoint_contract import verify_contract,EDITION_CONTRACT
class ContractTests(unittest.TestCase):
 def test_all_three_editions(self):
  self.assertEqual(set(EDITION_CONTRACT),{'linux-full','linux-compact','windows-compact'})
 def test_no_unsafe_claim(self):
  self.assertTrue(all(not x['qualified_native_runtime'] for x in EDITION_CONTRACT.values()))
 def test_missing_fails_closed(self):
  with tempfile.TemporaryDirectory() as d:
   result=verify_contract(d);self.assertFalse(result['pass']);self.assertEqual(len(result['issues']),3)
 def test_current_release_files(self):
  root=Path(__file__).resolve().parents[1];result=verify_contract(root);self.assertTrue(result['pass'],result['issues'])
 def test_read_only_role(self):
  for key in ('linux-compact','windows-compact'):
   self.assertEqual(EDITION_CONTRACT[key]['mode'],'read-only-supervision')
if __name__=='__main__':unittest.main()
