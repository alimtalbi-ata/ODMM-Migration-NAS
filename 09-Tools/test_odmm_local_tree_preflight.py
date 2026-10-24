"""Read-only preflight subprocess acceptance."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "odmm_local_tree_preflight.py"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux only")
class PreflightTests(unittest.TestCase):
    def invoke(self, source, target):
        return subprocess.run([sys.executable, str(TOOL), "--source", str(source),
                               "--target", str(target)], text=True,
                              capture_output=True, timeout=30)

    def test_safe_tree_ready_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            (source / "sub").mkdir(parents=True)
            (source / "sub" / "data").write_bytes(b"abc")
            result = self.invoke(source, target)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "READY_LOCAL_LAB_ONLY")
            self.assertEqual(report["regular_files"], 1)
            self.assertEqual(report["bytes"], 3)
            self.assertFalse(target.exists())

    def test_symlink_blocks_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            (source / "link").symlink_to(root)
            result = self.invoke(source, target)
            self.assertEqual(result.returncode, 2)
            self.assertIn("SYMLINK_OR_SPECIAL_UNSUPPORTED",
                          [x["code"] for x in json.loads(result.stdout)["findings"]])
            self.assertFalse(target.exists())

    def test_traversal_error_is_reported_and_blocks(self):
        import importlib.util
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location("odmm_preflight_test", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            real_walk = os.walk

            def failing_walk(*args, **kwargs):
                yield from real_walk(*args, **kwargs)
                kwargs["onerror"](PermissionError(13, "permission denied", str(source / "blocked")))

            with patch.object(module.os, "walk", failing_walk):
                _, _, findings = module.inspect(source, target)
            self.assertIn("SOURCE_TRAVERSAL_UNAVAILABLE", [x["code"] for x in findings])
            self.assertFalse(target.exists())

    def test_existing_target_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            result = self.invoke(source, target)
            self.assertEqual(result.returncode, 2)
            self.assertIn("TARGET_EXISTS",
                          [x["code"] for x in json.loads(result.stdout)["findings"]])


if __name__ == "__main__":
    unittest.main()
