"""Deterministic source mutation during a real local tree copy.

Uses a subprocess and a test-only module import shim to mutate the second
source file immediately after the first successful copy. No production code
injection hooks are added. NOT a NAS concurrency qualification.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

CLI = Path(__file__).resolve().parent / "odmm_local_tree_cli.py"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux only")
class ConcurrentSourceMutation(unittest.TestCase):
    def test_source_mutated_mid_run_is_not_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            (source / "a.bin").write_bytes(b"A" * 4096)
            second = source / "b.bin"
            second.write_bytes(b"B" * 4096)
            spec = importlib.util.spec_from_file_location("odmm_tree_cli_mutation", CLI)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            real_copy = module.run_lab_copy
            calls = [0]

            def copy_and_mutate(*args, **kwargs):
                result = real_copy(*args, **kwargs)
                calls[0] += 1
                if calls[0] == 1:
                    second.write_bytes(b"C" * 4096)
                return result

            module.run_lab_copy = copy_and_mutate
            result = module.main(["--source", str(source), "--target", str(target),
                                  "--ack-local-lab-only"])
            self.assertEqual(result, 1)
            self.assertEqual(calls[0], 1)
            self.assertTrue(target.exists())
            self.assertTrue((target / "a.bin").exists())
            self.assertFalse((target / "b.bin").exists())


if __name__ == "__main__":
    unittest.main()
