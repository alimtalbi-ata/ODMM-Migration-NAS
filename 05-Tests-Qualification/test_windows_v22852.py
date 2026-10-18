import ast
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Release22852(unittest.TestCase):
 def test_ui_parses(self):
  ast.parse((ROOT/'02-Sources/odmm_windows_compact_v22811.py').read_text(encoding='utf-8'))
 def test_keyboard_access(self):
  s=(ROOT/'02-Sources/odmm_windows_compact_v22811.py').read_text(encoding='utf-8')
  for term in ('tabs.enable_traversal()', '<F5>', '<Control-f>', 'lecture seule'):
   self.assertIn(term,s)
 def test_single_build_entrypoint_and_pinning(self):
  s=(ROOT/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').read_text()
  self.assertIn('WINDOWS-BUILD-REQUIREMENTS.txt',s)
  self.assertIn('pip check',s)
  self.assertIn('VERIFY-WINDOWS-ARTIFACTS.py',s)
 def test_dependency_pinned(self):
  s=(ROOT/'03-Build-Installation/WINDOWS-BUILD-REQUIREMENTS.txt').read_text()
  self.assertIn('pyinstaller==',s)
if __name__=='__main__': unittest.main()
