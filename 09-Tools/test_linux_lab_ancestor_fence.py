"""Ancestor-path fencing regressions. Local POSIX lab; no NAS writes.

Author: Abdelhalim Talbi.
"""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lab_verifier import _digest, verify_pair, VerificationError


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX lab only")
class AncestorFenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ancestor = self.root / "ancestor"
        self.parent = self.ancestor / "parent"
        self.parent.mkdir(parents=True)
        self.file = self.parent / "data.bin"
        self.file.write_bytes(b"fenced-content" * 4096)
        os.chmod(self.file, 0o640)

    def _during_hash(self, action):
        real_sha256 = hashlib.sha256

        class InterceptDigest:
            def __init__(self):
                self.inner = real_sha256()
                self.fired = False

            def update(self, data):
                self.inner.update(data)
                if not self.fired:
                    self.fired = True
                    action()

            def hexdigest(self):
                return self.inner.hexdigest()

        return patch("odmm_linux_lab_verifier.hashlib.sha256", side_effect=InterceptDigest)

    def test_stable_nested_ancestor_verifies(self):
        result = _digest(self.file)
        self.assertEqual(result["sha256"], hashlib.sha256(self.file.read_bytes()).hexdigest())

    def test_existing_symlink_ancestor_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.ancestor, target_is_directory=True)
        with self.assertRaisesRegex(VerificationError, "FILE_READ_FAILURE"):
            verify_pair(alias / "parent" / "data.bin", self.file)

    def test_ancestor_replaced_by_symlink_during_hash_refused(self):
        parked = self.root / "parked"
        victim = self.root / "victim"
        (victim / "parent").mkdir(parents=True)
        (victim / "parent" / "data.bin").write_bytes(self.file.read_bytes())

        def swap():
            self.ancestor.rename(parked)
            self.ancestor.symlink_to(victim, target_is_directory=True)

        with self._during_hash(swap):
            with self.assertRaisesRegex(VerificationError, "PATH_IDENTITY_CHANGED"):
                _digest(self.file)
        self.assertEqual((victim / "parent" / "data.bin").read_bytes(),
                         (parked / "parent" / "data.bin").read_bytes())

    def test_ancestor_replaced_by_directory_during_hash_refused(self):
        parked = self.root / "parked"

        def swap():
            self.ancestor.rename(parked)
            self.ancestor.mkdir()

        with self._during_hash(swap):
            with self.assertRaisesRegex(VerificationError, "PATH_IDENTITY_CHANGED"):
                _digest(self.file)

    def test_lexical_parent_traversal_refused(self):
        unsafe = self.root / "ancestor" / ".." / "ancestor" / "parent" / "data.bin"
        with self.assertRaisesRegex(VerificationError, "PATH_IDENTITY_CHANGED"):
            _digest(unsafe)


if __name__ == "__main__":
    unittest.main()
