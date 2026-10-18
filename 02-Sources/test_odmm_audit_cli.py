import tempfile, unittest
from pathlib import Path
from odmm_audit_cli import inventory

class AuditInventoryTests(unittest.TestCase):
    def test_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,'ok.py').write_text('x=1\n')
            Path(tmp,'test_ok.py').write_text('def test_x(): pass\n')
            value=inventory(tmp)
            self.assertEqual((value['modules'],value['test_modules']),(1,1))
            self.assertFalse(value['production_qualified'])
    def test_syntax_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp,'bad.py').write_text('def bad(:\n')
            self.assertEqual(inventory(tmp)['syntax_errors'][0]['module'],'bad.py')
    def test_missing_directory(self):
        with self.assertRaises(ValueError): inventory('/path/not/existing/odmm/audit')
