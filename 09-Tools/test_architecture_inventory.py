"""Regression tests for non-destructive architecture analysis."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inventory = load("INVENTORY-DEPENDENCIES.py", "inventory_dependencies")
reachability = load("REPORT-RUNTIME-REACHABILITY.py", "runtime_reachability")


class InventoryTests(unittest.TestCase):
    def test_imports_and_reverse_edges(self):
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory) / "02-Sources"
            src.mkdir()
            (src / "app.py").write_text("import service\n", encoding="utf-8")
            (src / "service.py").write_text("import json\n", encoding="utf-8")
            (src / "unused.py").write_text("pass\n", encoding="utf-8")
            result = inventory.scan(Path(directory))
            self.assertEqual(result["local_imports"]["app.py"], ["service"])
            self.assertEqual(result["reverse_local_imports"]["service"], ["app.py"])
            self.assertIn("unused.py", result["no_static_inbound_imports"])
            self.assertEqual(result["parse_errors"], {})

    def test_syntax_errors_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory) / "02-Sources"
            src.mkdir()
            (src / "broken.py").write_text("def broken(:\n", encoding="utf-8")
            result = inventory.scan(Path(directory))
            self.assertIn("broken.py", result["parse_errors"])

    def test_reachability_cycle_and_unrelated_module(self):
        data = {"local_imports": {
            "app.py": ["service"],
            "service.py": ["app"],
            "other.py": [],
        }}
        result = reachability.report(data, ("app.py",))
        self.assertEqual(result["statically_reachable"], ["app.py", "service.py"])
        self.assertEqual(result["not_reachable_from_selected_entrypoints"], ["other.py"])
        self.assertEqual(result["missing_entrypoints"], [])

    def test_missing_entrypoint_is_reported(self):
        result = reachability.report({"local_imports": {}}, ("missing.py",))
        self.assertEqual(result["missing_entrypoints"], ["missing.py"])


if __name__ == "__main__":
    unittest.main()
