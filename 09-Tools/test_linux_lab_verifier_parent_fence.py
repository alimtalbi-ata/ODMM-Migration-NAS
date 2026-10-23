"""Descriptor-relative verifier regressions: isolated POSIX lab only.

Author: Abdelhalim Talbi. No production NAS operations.
"""
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lab_verifier import _digest, verify_pair, VerificationError


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX only")
class ParentFenceVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.parent = self.root / "parent"
        self.parent.mkdir()
        self.file = self.parent / "file.bin"
        self.file.write_bytes(b"test-data" * 2048)
        os.chmod(self.file, 0o640)

    def tearDown(self):
        self.temp.cleanup()

    def _inject_after_first_chunk(self, change):
        original_sha256 = hashlib.sha256
        class InjectingDigest:
            def __init__(self):
                self.real = original_sha256()
                self.fired = False
            def update(self, data):
                self.real.update(data)
                if not self.fired:
                    self.fired = True
                    change()
            def hexdigest(self):
                return self.real.hexdigest()
        return patch("odmm_linux_lab_verifier.hashlib.sha256", side_effect=InjectingDigest)

    def test_unchanged_descriptor_hash_matches(self):
        report = _digest(self.file)
        self.assertEqual(report["sha256"], hashlib.sha256(self.file.read_bytes()).hexdigest())
        self.assertEqual(report["mode"], 0o640)

    def test_parent_replaced_with_symlink_mid_hash_is_refused(self):
        parked = self.root / "parked"
        victim = self.root / "victim"
        victim.mkdir()
        (victim / "file.bin").write_bytes(self.file.read_bytes())
        def change():
            self.parent.rename(parked)
            self.parent.symlink_to(victim, target_is_directory=True)
        with self._inject_after_first_chunk(change):
            with self.assertRaisesRegex(VerificationError, "PATH_IDENTITY_CHANGED"):
                _digest(self.file)
        self.assertEqual((victim / "file.bin").read_bytes(), (parked / "file.bin").read_bytes())

    def test_leaf_replaced_with_symlink_mid_hash_is_refused(self):
        parked = self.parent / "parked"
        victim = self.root / "victim.bin"
        victim.write_bytes(b"untouched")
        def change():
            self.file.rename(parked)
            self.file.symlink_to(victim)
        with self._inject_after_first_chunk(change):
            with self.assertRaisesRegex(VerificationError, "PATH_IDENTITY_CHANGED|FILE_CHANGED_DURING_VERIFICATION"):
                _digest(self.file)
        self.assertEqual(victim.read_bytes(), b"untouched")

    def test_parent_symlink_is_refused_before_read(self):
        alias = self.root / "alias"
        alias.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaisesRegex(VerificationError, "FILE_READ_FAILURE"):
            verify_pair(alias / "file.bin", self.file)

    def test_metadata_only_change_during_hash_is_refused(self):
        with self._inject_after_first_chunk(lambda: os.chmod(self.file, 0o600)):
            with self.assertRaisesRegex(VerificationError, "FILE_CHANGED_DURING_VERIFICATION"):
                _digest(self.file)

    def test_matching_pair_still_verifies(self):
        second = self.parent / "copy.bin"
        second.write_bytes(self.file.read_bytes())
        os.chmod(second, 0o640)
        self.assertTrue(verify_pair(self.file, second)["verified"])


if __name__ == "__main__":
    unittest.main()
