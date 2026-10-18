import sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'02-Sources'))
from odmm_static_reachability import analyze
class ReachabilityTests(unittest.TestCase):
 def test_transitive_and_unreached(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);s=root/'02-Sources';s.mkdir()
   (s/'entry.py').write_text('import middle\n')
   (s/'middle.py').write_text('from leaf import go\n')
   (s/'leaf.py').write_text('def go():pass\n')
   (s/'unused.py').write_text('pass\n')
   r=analyze(root,['02-Sources/entry.py'])
   self.assertEqual(r['reachable_modules'],['entry','leaf','middle'])
   self.assertEqual(r['not_statically_reached'],['unused'])
 def test_missing_entry(self):
  with tempfile.TemporaryDirectory() as d:
   (Path(d)/'02-Sources').mkdir()
   self.assertEqual(analyze(d,['absent.py'])['missing_entrypoints'],['absent.py'])
 def test_dynamic_import_flag(self):
  with tempfile.TemporaryDirectory() as d:
   s=Path(d)/'02-Sources';s.mkdir()
   (s/'entry.py').write_text('import importlib\nimportlib.import_module("hidden")\n')
   (s/'hidden.py').write_text('pass\n')
   r=analyze(d,['02-Sources/entry.py'])
   self.assertEqual(len(r['dynamic_import_indicators']),1)
   self.assertIn('hidden',r['not_statically_reached'])
if __name__=='__main__':unittest.main()
