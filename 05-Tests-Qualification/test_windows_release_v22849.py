import ast
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util
R = Path(__file__).resolve().parents[1]
class WindowsRelease(unittest.TestCase):
 def test_ui_syntax(self):
  ast.parse((R/'02-Sources/odmm_windows_compact_v22811.py').read_text())
 def test_ui_sort_and_scroll(self):
  ui=(R/'02-Sources/odmm_windows_compact_v22811.py').read_text()
  self.assertIn('def sort_table(column)',ui)
  self.assertIn('ttk.Scrollbar',ui)
  self.assertIn('selectmode="browse"',ui)
 def test_build_requires_both_artifacts(self):
  script=(R/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').read_text()
  self.assertIn('VERIFY-WINDOWS-ARTIFACTS.py',script)
  self.assertIn('INNO_ISCC',script)
  self.assertIn('ODMM_WHEELHOUSE',script)
 def test_installer_is_per_user(self):
  iss=(R/'02-Sources/ODMM-COMPACT-WINDOWS-V22811.iss').read_text()
  self.assertIn('PrivilegesRequired=lowest',iss)
  self.assertIn('ODMM_EXE',iss)
 def test_verifier_rejects_missing(self):
  p=R/'03-Build-Installation/VERIFY-WINDOWS-ARTIFACTS.py'
  spec=importlib.util.spec_from_file_location('verify_windows',p)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  with TemporaryDirectory() as tmp:
   with self.assertRaises(ValueError): module.verify(tmp,"7.9.31")
if __name__=='__main__':unittest.main()
