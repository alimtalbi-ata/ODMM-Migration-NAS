"""ODMM V201.4 fixture regression tests. Author: Abdelhalim Talbi."""
import tempfile
import unittest
from pathlib import Path
from odmm_fidelity_fixtures_v2014 import create_fixtures, verify_fixtures

class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/"dataset"
    def test_create_verify(self):
        m=create_fixtures(self.root); self.assertTrue(verify_fixtures(self.root,m))
    def test_repeat_reproducible(self):
        a=create_fixtures(self.root)
        b=create_fixtures(Path(self.tmp.name)/"second")
        self.assertEqual(a,b)
    def test_corruption(self):
        m=create_fixtures(self.root); (self.root/"binary.bin").write_bytes(b"bad")
        self.assertFalse(verify_fixtures(self.root,m))
    def test_missing(self):
        m=create_fixtures(self.root); (self.root/"empty").unlink()
        self.assertFalse(verify_fixtures(self.root,m))
    def test_extra(self):
        m=create_fixtures(self.root); (self.root/"extra").write_text("x")
        self.assertFalse(verify_fixtures(self.root,m))
    def test_manifest_tamper(self):
        m=create_fixtures(self.root); m["entries"][0]["path"]="tampered"
        self.assertFalse(verify_fixtures(self.root,m))
    def test_existing_destination(self):
        self.root.mkdir()
        with self.assertRaises(ValueError): create_fixtures(self.root)
    def test_budget(self):
        with self.assertRaises(ValueError): create_fixtures(self.root,max_bytes=1024)
    def test_no_cutover(self):
        m=create_fixtures(self.root)
        self.assertFalse(m["cutover_authorized"])
        self.assertFalse(m["acl_applied"])
    def test_symlink_detected(self):
        m=create_fixtures(self.root); (self.root/"relative-link").unlink(); (self.root/"relative-link").symlink_to("empty")
        self.assertFalse(verify_fixtures(self.root,m))

if __name__=="__main__": unittest.main()
