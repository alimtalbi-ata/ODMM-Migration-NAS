import importlib.util
import tempfile
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("preflight", ROOT / "03-Build-Installation/PREFLIGHT-WINDOWS.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
class PreflightTests(unittest.TestCase):
    def test_real_tree(self): self.assertTrue(mod.check(ROOT))
    def test_missing_inputs(self):
        with tempfile.TemporaryDirectory() as d: self.assertFalse(mod.check(d))
    def test_single_build_entrypoint(self):
        self.assertTrue((ROOT / "03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd").is_file())
    def test_build_calls_preflight(self):
        self.assertIn("PREFLIGHT-WINDOWS.py", (ROOT / "03-Build-Installation/BUILD-WINDOWS-COMPACT.cmd").read_text())
if __name__ == "__main__": unittest.main()
