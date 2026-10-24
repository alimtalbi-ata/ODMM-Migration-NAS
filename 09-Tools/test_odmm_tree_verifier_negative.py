"""Negative tests for independent post-copy tree verifier.

No production NAS integration. Deliberately corrupts only disposable temp files.
"""
import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parent / "odmm_local_tree_cli.py"
spec = importlib.util.spec_from_file_location("odmm_local_tree_cli_under_test", MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX only")
class TreeVerifierNegativeTests(unittest.TestCase):
    def test_byte_corruption_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst = root / "src", root / "dst"
            src.mkdir()
            dst.mkdir()
            (src / "file").write_bytes(b"abcdef")
            (dst / "file").write_bytes(b"abcXef")
            with self.assertRaisesRegex(RuntimeError, "POST_COPY_HASH_MISMATCH"):
                mod.verify_tree(src, dst, [], [Path("file")])

    def test_mode_drift_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst = root / "src", root / "dst"
            src.mkdir()
            dst.mkdir()
            (src / "file").write_bytes(b"same")
            (dst / "file").write_bytes(b"same")
            (src / "file").chmod(0o640)
            (dst / "file").chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "POST_COPY_FILE_MODE_MISMATCH"):
                mod.verify_tree(src, dst, [], [Path("file")])

    def test_target_traversal_failure_detected(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst = root / "src", root / "dst"
            src.mkdir()
            dst.mkdir()
            real_walk = os.walk

            def interrupted_walk(*args, **kwargs):
                yield from real_walk(*args, **kwargs)
                kwargs["onerror"](PermissionError(13, "denied", str(dst / "inaccessible")))

            with patch.object(mod.os, "walk", interrupted_walk):
                with self.assertRaisesRegex(RuntimeError, "POST_COPY_TARGET_TRAVERSAL_FAILED"):
                    mod.verify_tree(src, dst, [], [])

    def test_unexpected_extra_file_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst = root / "src", root / "dst"
            src.mkdir()
            dst.mkdir()
            (src / "file").write_bytes(b"same")
            (dst / "file").write_bytes(b"same")
            (dst / "unexpected").write_bytes(b"unexpected")
            with self.assertRaisesRegex(RuntimeError, "POST_COPY_INVENTORY_MISMATCH"):
                mod.verify_tree(src, dst, [], [Path("file")])


if __name__ == "__main__":
    unittest.main()
