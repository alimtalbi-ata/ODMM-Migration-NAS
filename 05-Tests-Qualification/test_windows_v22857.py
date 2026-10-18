import ast, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
UI=ROOT/'02-Sources/odmm_windows_compact_v22811.py'
class StatusDisplayTests(unittest.TestCase):
 def test_syntax(self): ast.parse(UI.read_text(encoding='utf-8'))
 def test_tags(self):
  s=UI.read_text(encoding='utf-8'); self.assertIn('tree.tag_configure(tag, foreground=foreground)',s)
 def test_unknown_fallback(self):
  s=UI.read_text(encoding='utf-8'); self.assertIn('else "UNKNOWN"',s)
 def test_read_only(self): self.assertIn('read-only supervisor',UI.read_text())
 def test_version_sync(self):
  self.assertIn('7.9.27',UI.read_text());self.assertIn('#define MyAppVersion ODMM_VERSION',(ROOT/'03-Build-Installation/ODMM-COMPACT-WINDOWS.iss').read_text());self.assertIn('ODMM_VERSION=7.9.27',(ROOT/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').read_text())
if __name__=='__main__': unittest.main()
