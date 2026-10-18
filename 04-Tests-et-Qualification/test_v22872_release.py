import pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class ReleaseTests(unittest.TestCase):
 def test_workflow_checks_report(self):
  s=(ROOT/'.github/workflows/windows-compact-release.yml').read_text(); self.assertIn('if (!$report.passed',s)
 def test_installer_guard(self):
  s=(ROOT/'03-Build-Installation/TEST-WINDOWS-INSTALL.ps1').read_text(); self.assertIn('ODMM_ALLOW_DISPOSABLE_INSTALL_TEST',s)
 def test_build_version(self):
  s=(ROOT/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').read_text(); self.assertIn('ODMM_VERSION=7.9.28',s)
if __name__=='__main__': unittest.main()
