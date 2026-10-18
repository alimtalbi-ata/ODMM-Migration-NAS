import json, tempfile, unittest, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'09-Tools'))
from decision_matrix_v22822 import analyze
class DecisionTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
  for folder in ('02-Sources','07-Rapports'):(self.root/folder).mkdir()
  (self.root/'07-Rapports/REACHABILITY-V228.19.json').write_text(json.dumps({'reachable_modules':['main']}))
  (self.root/'07-Rapports/runtime-inventory-v22821.json').write_text(json.dumps({'references':[{'kind':'python-file','value':'worker.py'}]}))
  for name,content in {'main.py':'import helper','worker.py':'pass','helper.py':'pass','old_v1.py':'pass','old_v2.py':'pass','test_main.py':'pass'}.items():(self.root/'02-Sources'/name).write_text(content)
 def tearDown(self):self.temp.cleanup()
 def test_roots_protected(self):
  rows={r['module']:r for r in analyze(self.root)['modules']}
  self.assertEqual(rows['main']['decision'],'KEEP_PROTECTED');self.assertEqual(rows['worker']['decision'],'KEEP_PROTECTED')
 def test_import_review(self):
  rows={r['module']:r for r in analyze(self.root)['modules']};self.assertEqual(rows['helper']['decision'],'REVIEW_DEPENDENCY')
 def test_historical_review_no_deletion(self):
  result=analyze(self.root);rows={r['module']:r for r in result['modules']}
  self.assertEqual(rows['old_v1']['decision'],'REVIEW_UNRESOLVED');self.assertFalse(result['deletion_authorized'])
  self.assertTrue(all(not x['deletion_authorized'] for x in result['modules']))
 def test_version_family(self):self.assertGreaterEqual(analyze(self.root)['multiple_version_families'],1)
 def test_tests_preserved_for_review(self):
  rows={r['module']:r for r in analyze(self.root)['modules']};self.assertEqual(rows['test_main']['decision'],'REVIEW_TEST_COVERAGE')
if __name__=='__main__':unittest.main()
