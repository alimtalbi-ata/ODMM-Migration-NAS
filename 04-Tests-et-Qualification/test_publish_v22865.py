import tempfile, unittest, importlib.util
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'03-Build-Installation'/'PUBLISH-WINDOWS-ARTIFACTS.py'
spec=importlib.util.spec_from_file_location('publish',p); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class PublishTests(unittest.TestCase):
 def test_missing_rejected_preserves_old(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); (root/'binary').mkdir(); (root/'binary'/'old').write_text('ok'); (root/'stage').mkdir()
   with self.assertRaises(RuntimeError):m.publish(root/'stage',root/'binary','7.9.21')
   self.assertEqual((root/'binary'/'old').read_text(),'ok')
 def test_success_preserves_backup(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); stage=root/'stage'; (stage/'portable').mkdir(parents=True); (stage/'installer').mkdir()
   for x in ['portable/ODMM-Compact.exe','installer/ODMM-Compact-Setup-V7.9.21.exe','SHA256-WINDOWS.json','BUILD-STATUS.json']:(stage/x).write_text('mock')
   (root/'binary').mkdir(); (root/'binary'/'old').write_text('ok')
   m.publish(stage,root/'binary','7.9.21')
   self.assertTrue((root/'binary'/'portable'/'ODMM-Compact.exe').exists());self.assertTrue((root/'binary.previous'/'old').exists())
if __name__=='__main__':unittest.main()
