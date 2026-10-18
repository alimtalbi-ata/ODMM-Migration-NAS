from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
class TestWindowsInstallContract(unittest.TestCase):
    def test_single_entrypoint(self):
        self.assertIn('ODMM_VERSION=7.9.27', (ROOT/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').read_text())
    def test_workflow_runs_install(self):
        s=(ROOT/'.github/workflows/windows-compact-release.yml').read_text()
        self.assertIn('TEST-WINDOWS-INSTALL.ps1',s)
        self.assertIn('if: success()',s)
    def test_no_destructive_existing_install(self):
        s=(ROOT/'03-Build-Installation/TEST-WINDOWS-INSTALL.ps1').read_text()
        self.assertIn('Refusing to overwrite an existing installation',s)
        self.assertIn('unins000.exe',s)
        self.assertIn('WINDOWS-INSTALL-SMOKE.json',s)
if __name__ == '__main__': unittest.main()
