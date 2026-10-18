import importlib.util
import tempfile
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "03-Build-Installation" / "VERIFY-WINDOWS-ARTIFACTS.py"
spec = importlib.util.spec_from_file_location("verify_odmm", FILE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ArtifactVerification(unittest.TestCase):
    def test_missing_files_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError): mod.verify(d,"7.9.29")
    def test_fake_mz_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            x = Path(d)/"portable/ODMM-Compact.exe"
            x.parent.mkdir()
            x.write_bytes(b"MZ" + bytes(2048))
            with self.assertRaisesRegex(ValueError, "Invalid PE header offset"): mod.verify(d,"7.9.29")
    def test_bad_pe_signature_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            x = Path(d)/"portable/ODMM-Compact.exe"
            x.parent.mkdir()
            b=bytearray(2048);b[:2]=b"MZ";b[0x3c:0x40]=(128).to_bytes(4,"little");x.write_bytes(b)
            with self.assertRaisesRegex(ValueError, "Invalid PE signature"): mod.verify(d,"7.9.29")
    def test_build_stages_before_publication(self):
        s=(FILE.parent/"BUILD-WINDOWS-COMPACT.cmd").read_text()
        self.assertIn('rmdir /s /q "%STAGE%"',s)
        self.assertNotIn('del /q "%OUT%',s)
        self.assertLess(s.index('VERIFY-WINDOWS-ARTIFACTS.py'),s.index('PUBLISH-WINDOWS-ARTIFACTS.py'))

if __name__ == "__main__": unittest.main()
