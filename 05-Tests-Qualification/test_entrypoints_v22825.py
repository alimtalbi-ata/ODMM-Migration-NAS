import subprocess, tempfile, unittest, shutil
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
LAUNCH = ROOT / '03-Build-Installation' / 'RUN-LINUX-COMPACT.sh'
CHECK = ROOT / '03-Build-Installation' / 'CHECK-ENTRYPOINTS.sh'
class TestEntryPoints(unittest.TestCase):
    def test_shell_syntax(self):
        for path in (LAUNCH,CHECK):
            self.assertEqual(subprocess.run(['bash','-n',str(path)],capture_output=True).returncode,0)
    def test_preflight(self):
        r=subprocess.run(['bash',str(CHECK)],cwd='/',capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout.count('PASS '),6)
    def test_linux_compact_help_from_other_cwd(self):
        r=subprocess.run(['bash',str(LAUNCH),'--help'],cwd='/',capture_output=True,text=True,timeout=20)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('--demo-overview',r.stdout)
    def test_linux_compact_demo_from_other_cwd(self):
        r=subprocess.run(['bash',str(LAUNCH),'--demo-overview'],cwd='/',capture_output=True,text=True,timeout=20)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('SYNTHETIC',r.stdout)
    def test_missing_entry_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp); (d/'03-Build-Installation').mkdir();(d/'02-Sources').mkdir()
            shutil.copy2(LAUNCH,d/'03-Build-Installation'/LAUNCH.name)
            r=subprocess.run(['bash',str(d/'03-Build-Installation'/LAUNCH.name)],capture_output=True,text=True)
            self.assertEqual(r.returncode,21)
            self.assertIn('missing',r.stderr)
if __name__=='__main__': unittest.main()
