import unittest
from pathlib import Path
import importlib.util, tempfile
BASE = Path(__file__).resolve().parents[1] / "03-Build-Installation"
class WindowsRelease(unittest.TestCase):
    def test_versions_and_sources(self):
        cmd = (BASE / "BUILD-WINDOWS-COMPACT.cmd").read_text()
        iss = (BASE / "ODMM-COMPACT-WINDOWS.iss").read_text()
        self.assertIn("ODMM-COMPACT-WINDOWS.iss", cmd)
        self.assertIn('#define MyAppVersion ODMM_VERSION', iss)
        self.assertIn('/DODMM_VERSION="%ODMM_VERSION%"', cmd)
        self.assertIn("ODMM-Compact-Setup-V{#MyAppVersion}", iss)
        self.assertIn('Source: "{#ODMM_EXE}"', iss)
        self.assertIn("OutputDir={#ODMM_OUTPUT}", iss)
        self.assertIn("PrivilegesRequired=lowest", iss)
        self.assertIn("--onefile", cmd)
    def test_missing_artifacts_rejected(self):
        spec=importlib.util.spec_from_file_location("verify",BASE / "VERIFY-WINDOWS-ARTIFACTS.py")
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError): mod.verify(temp,"7.9.31")
    def test_streaming_hash(self):
        spec=importlib.util.spec_from_file_location("verify",BASE / "VERIFY-WINDOWS-ARTIFACTS.py")
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        import hashlib
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"sample.bin"; path.write_bytes(b"abc"*1000)
            self.assertEqual(mod.sha256_file(path),hashlib.sha256(path.read_bytes()).hexdigest())
if __name__=="__main__": unittest.main()
