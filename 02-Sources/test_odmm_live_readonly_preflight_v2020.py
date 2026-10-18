import tempfile
import unittest
from pathlib import Path
from odmm_live_readonly_preflight_v2020 import observe, inspect_pair, verify

class TestLivePreflight(unittest.TestCase):
    def test_pair(self):
        with tempfile.TemporaryDirectory() as t:
            a=Path(t)/'a'; b=Path(t)/'b'; a.mkdir(); b.mkdir()
            report=inspect_pair(a,b)
            self.assertTrue(verify(report))
            self.assertFalse(report['cutover_authorized'])
            self.assertFalse(report['writes_to_nas'])
            self.assertEqual(report['source']['acl_smb'],'UNVERIFIED')
            self.assertEqual(list(a.iterdir()),[])
            self.assertEqual(list(b.iterdir()),[])
    def test_tampering(self):
        with tempfile.TemporaryDirectory() as t:
            a=Path(t)/'a'; b=Path(t)/'b'; a.mkdir(); b.mkdir()
            r=inspect_pair(a,b); r['status']='PASS'
            self.assertFalse(verify(r))
    def test_overlap(self):
        with tempfile.TemporaryDirectory() as t:
            a=Path(t)/'a'; b=a/'b'; b.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError,'OVERLAPPING'): inspect_pair(a,b)
    def test_symlink_root(self):
        with tempfile.TemporaryDirectory() as t:
            a=Path(t)/'a'; a.mkdir(); link=Path(t)/'link'; link.symlink_to(a)
            with self.assertRaisesRegex(ValueError,'SYMLINK'): observe(link)
    def test_missing(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(ValueError,'ROOT_NOT_DIRECTORY'): observe(Path(t)/'missing')
    def test_file(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'file'; p.write_text('x')
            with self.assertRaisesRegex(ValueError,'ROOT_NOT_DIRECTORY'): observe(p)

if __name__=='__main__': unittest.main()
