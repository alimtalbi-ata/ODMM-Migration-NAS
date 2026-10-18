import subprocess, pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
ENTRY=ROOT/'03-Build-Installation/RUN-LINUX-FULL.sh'
class LinuxFullLauncherTests(unittest.TestCase):
 def run_script(self,*args):
  return subprocess.run(['bash',str(ENTRY),*args],cwd='/tmp',capture_output=True,text=True,timeout=60)
 def test_help(self):
  p=self.run_script('--help'); self.assertEqual(p.returncode,0,p.stderr); self.assertIn('read-only',p.stdout)
 def test_unknown_command_fails_closed(self):
  p=self.run_script('--migrate'); self.assertEqual(p.returncode,33)
 def test_qualification_from_different_cwd(self):
  p=self.run_script('--check'); self.assertEqual(p.returncode,0,p.stderr); self.assertIn('nas-live=NOT_QUALIFIED',p.stdout)
 def test_source_exists(self):
  self.assertTrue((ROOT/'02-Sources/test_odmm_market_readiness_v22812.py').is_file())
if __name__=='__main__': unittest.main()
