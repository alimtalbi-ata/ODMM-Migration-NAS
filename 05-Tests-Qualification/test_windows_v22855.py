import ast
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "02-Sources" / "odmm_windows_compact_v22811.py"
class WindowsUIV22855(unittest.TestCase):
    def test_syntax(self): ast.parse(SRC.read_text(encoding="utf-8"))
    def test_search_navigation(self):
        source = SRC.read_text(encoding="utf-8")
        self.assertIn('tabs.select(jobs)', source)
        self.assertIn('search_entry.selection_range(0, "end")', source)
    def test_escape_clear(self):
        self.assertIn('root.bind("<Escape>", clear_search)', SRC.read_text(encoding="utf-8"))
if __name__ == "__main__": unittest.main()
