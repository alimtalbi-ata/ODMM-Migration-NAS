import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
class BuildContract(unittest.TestCase):
    def test_version_consistent(self):
        script=(ROOT/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').read_text()
        flow=(ROOT/'.github/workflows/windows-compact-release.yml').read_text()
        self.assertIn('ODMM_VERSION=7.9.25',script)
        self.assertIn('ODMM-Compact-Setup-V7.9.25.exe',flow)
    def test_staged_publication_and_validation(self):
        s=(ROOT/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').read_text()
        self.assertLess(s.index('VERIFY-WINDOWS-ARTIFACTS.py" "%STAGE%"'),s.index('PUBLISH-WINDOWS-ARTIFACTS.py'))
        self.assertIn('VALIDATE-WINDOWS-RELEASE.py" "%OUT%"',s)
    def test_native_runner(self):
        flow=(ROOT/'.github/workflows/windows-compact-release.yml').read_text()
        self.assertIn('runs-on: windows-2022',flow)
        self.assertIn('BUILD-WINDOWS-COMPACT.cmd',flow)
        self.assertIn('upload-artifact@v4',flow)
if __name__=='__main__': unittest.main()
