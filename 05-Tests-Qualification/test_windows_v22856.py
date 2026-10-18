import ast
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
UI=ROOT/'02-Sources/odmm_windows_compact_v22811.py'
class DetailPanelTests(unittest.TestCase):
 def test_syntax(self): ast.parse(UI.read_text(encoding='utf-8'))
 def test_scrollable_readonly_detail(self):
  s=UI.read_text(encoding='utf-8');self.assertIn('detail_text = tk.Text',s);self.assertIn('detail_text.configure(state="disabled")',s);self.assertIn('detail_scroll = ttk.Scrollbar',s)
 def test_selection_accessibility(self):
  s=UI.read_text(encoding='utf-8');self.assertIn('tree.bind("<Return>", select_job)',s);self.assertIn('tree.bind("<Double-1>", select_job)',s)
 def test_packaging_version(self):
  self.assertIn('7.9.14',(ROOT/'03-Build-Installation/ODMM-COMPACT-WINDOWS.iss').read_text());self.assertIn('Setup-V7.9.14.exe',(ROOT/'03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd').read_text())
if __name__=='__main__': unittest.main()
