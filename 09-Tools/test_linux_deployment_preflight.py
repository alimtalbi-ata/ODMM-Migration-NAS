"""Non-destructive Linux preflight contract tests; no NAS required."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / "03-Build-Installation/ODMM-LINUX-PREFLIGHT.py"
spec = importlib.util.spec_from_file_location("odmm_linux_preflight", PREFLIGHT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class LinuxPreflightTests(unittest.TestCase):
    def test_compact_contract(self):
        result = module.inspect(ROOT, "compact")
        self.assertFalse(result["nas_migration_qualified"])
        self.assertTrue(result["checks"]["compact_entrypoint"])
        self.assertEqual(result["edition"], "compact")

    def test_full_contract(self):
        result = module.inspect(ROOT, "full")
        self.assertIn("sqlite_available", result["checks"])
        self.assertIn("flock_available", result["checks"])
        self.assertFalse(result["nas_migration_qualified"])

    def test_missing_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = module.inspect(Path(tmp), "full")
            self.assertFalse(result["passed"])
            self.assertFalse(result["checks"]["sources_available"])

    def test_cli_json(self):
        p = subprocess.run([sys.executable, str(PREFLIGHT), "--edition", "compact", "--root", str(ROOT)], capture_output=True, text=True)
        data = json.loads(p.stdout)
        self.assertEqual(data["edition"], "compact")
        self.assertEqual(p.returncode, 0 if data["passed"] else 1)

if __name__ == "__main__":
    unittest.main()
