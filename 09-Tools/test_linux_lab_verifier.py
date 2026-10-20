"""Local verifier: byte corruption, POSIX mode drift and symlink safety."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lab_verifier import verify_pair, VerificationError

class LabVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.src, self.dst = root / "src", root / "dst"
        self.src.write_bytes(b"sample" * 1000)
        self.dst.write_bytes(self.src.read_bytes())
        os.chmod(self.src, 0o600)
        os.chmod(self.dst, 0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def test_matching_files(self):
        result = verify_pair(self.src, self.dst)
        self.assertTrue(result["verified"])
        self.assertFalse(result["nas_acl_qualified"])

    def test_content_corruption(self):
        self.dst.write_bytes(b"sample" * 999 + b"corrupt")
        with self.assertRaisesRegex(VerificationError, "CONTENT_MISMATCH"):
            verify_pair(self.src, self.dst)

    def test_mode_mismatch(self):
        os.chmod(self.dst, 0o644)
        with self.assertRaisesRegex(VerificationError, "POSIX_MODE_MISMATCH"):
            verify_pair(self.src, self.dst)

    def test_symlink_refused(self):
        self.dst.unlink()
        self.dst.symlink_to(self.src)
        with self.assertRaisesRegex(VerificationError, "SYMLINK_REFUSED"):
            verify_pair(self.src, self.dst)

if __name__ == "__main__":
    unittest.main()
