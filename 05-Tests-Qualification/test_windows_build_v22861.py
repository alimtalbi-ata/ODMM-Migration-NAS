import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class TestBuild(unittest.TestCase):
 def test_output(self): self.assertIn('set "OUT=%ROOT%\\binary"',(ROOT/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').read_text())
 def test_setup_version(self): self.assertIn('#define MyAppVersion ODMM_VERSION',(ROOT/'03-Build-Installation/ODMM-COMPACT-WINDOWS.iss').read_text())
 def test_expected_name(self): self.assertIn('ODMM-Compact-Setup-V{version}.exe',(ROOT/'03-Build-Installation/VERIFY-WINDOWS-ARTIFACTS.py').read_text())
 def test_no_fake_exe(self): self.assertFalse(list((ROOT/'binary').rglob('*.exe')))
if __name__=='__main__': unittest.main()
