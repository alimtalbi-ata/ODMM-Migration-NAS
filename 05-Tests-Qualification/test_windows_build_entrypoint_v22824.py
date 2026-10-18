from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class TestWindowsBuildEntrypoint(unittest.TestCase):
 def test_canonical_present(self):
  self.assertTrue((ROOT/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').is_file())
 def test_source_dependencies(self):
  for name in ('BUILD-WINDOWS-COMPACT-V22811.cmd','odmm_windows_compact_v22811.py','ODMM-COMPACT-WINDOWS-V22811.iss'):
   with self.subTest(name=name):self.assertTrue((ROOT/'02-Sources'/name).is_file())
 def test_canonical_uses_explicit_source_paths(self):
  s=(ROOT/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').read_text()
  self.assertIn('set "SRC=%ROOT%\\02-Sources"',s)
  self.assertIn('%SRC%\\odmm_windows_compact_v22811.py',s)
  self.assertIn('VALIDATE-WINDOWS-RELEASE.py',s)
 def test_legacy_wrapper_uses_canonical(self):
  s=(ROOT/'03-Build-Installation/BUILD-WINDOWS-COMPACT-V22811.cmd').read_text()
  self.assertIn('call "%~dp0BUILD-WINDOWS-COMPACT.cmd"',s)
if __name__=='__main__':unittest.main()
