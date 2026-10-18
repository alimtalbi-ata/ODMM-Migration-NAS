import unittest
from pathlib import Path
from unittest.mock import patch
from importlib.util import spec_from_file_location, module_from_spec

p = Path(__file__).with_name('CHECK-WINDOWS-TOOLCHAIN.py')
spec = spec_from_file_location('toolchain', p)
m = module_from_spec(spec)
spec.loader.exec_module(m)

class TestToolchain(unittest.TestCase):
    def test_missing_inno_is_not_ready(self):
        with patch.object(m.subprocess, 'run') as run:
            run.return_value.returncode = 0
            report = m.inspect_toolchain('/not/a/real/iscc.exe')
        self.assertFalse(report['ready'])
        self.assertFalse(report['checks']['inno_compiler_exists'])
    def test_report_contains_all_checks(self):
        with patch.object(m.subprocess, 'run') as run:
            run.return_value.returncode = 0
            report = m.inspect_toolchain('/missing')
        self.assertEqual(report['schema'], 1)
        self.assertIn('tkinter_importable', report['checks'])
        self.assertIn('pyinstaller_importable', report['checks'])

if __name__ == '__main__': unittest.main()
