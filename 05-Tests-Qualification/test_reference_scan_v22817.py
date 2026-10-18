import tempfile,unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'09-Tools'))
from reference_scan import scan
class TestReferences(unittest.TestCase):
 def test_import_and_shell(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d);(r/'target.py').write_text('value=1');(r/'consumer.py').write_text('import target');(r/'run.sh').write_text('python target.py');a=scan(r);x=next(i for i in a['modules'] if i['module']=='target.py');self.assertEqual(x['classification'],'referenced');self.assertGreaterEqual(x['reference_count'],2)
 def test_unreferenced_not_called_dead(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d);(r/'alone.py').write_text('value=1');a=scan(r);self.assertEqual(a['modules'][0]['classification'],'manual_review')
 def test_entrypoint_candidate(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d);(r/'app.py').write_text('if __name__ == "__main__":\n print("hi")\n');a=scan(r);self.assertEqual(a['modules'][0]['classification'],'entrypoint_candidate')
if __name__=='__main__':unittest.main()
