import os
import tempfile
import unittest
from pathlib import Path
from odmm_sparse_ads_preflight_v2017 import sparse_extents, compare_sparse, ads_inventory, preflight

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'src').mkdir(); (self.root/'dst').mkdir()
        self.a = self.root/'src'/'a'; self.b = self.root/'dst'/'a'
        for p in (self.a,self.b):
            with p.open('wb') as f:
                f.write(b'A'); f.seek(8192); f.write(b'Z')
    def test_sparse(self):
        self.assertIn(sparse_extents(self.a)['status'], ('OBSERVED','UNSUPPORTED'))
    def test_sparse_comparison(self):
        self.assertIn(compare_sparse(self.a,self.b)['status'], ('MATCH','UNVERIFIED'))
    def test_sparse_mismatch(self):
        self.b.write_bytes(b'X')
        self.assertIn(compare_sparse(self.a,self.b)['status'], ('MISMATCH','UNVERIFIED'))
    def test_symlink_refused(self):
        link = self.root/'link'; link.symlink_to(self.a)
        with self.assertRaises(ValueError): sparse_extents(link)
    def test_preflight(self):
        r=preflight(self.root/'src',self.root/'dst',require_ads=True)
        self.assertFalse(r['cutover_authorized']); self.assertFalse(r['silent_fallback_allowed'])
        self.assertIn('ADS',r['checks']['ads'].upper()) if False else self.assertIn('WINDOWS',r['checks']['ads'])
    def test_preflight_symlink(self):
        link=self.root/'alias'; link.symlink_to(self.root/'src')
        with self.assertRaises(ValueError): preflight(link,self.root/'dst')
    def test_ads_platform(self):
        self.assertIn(ads_inventory(self.a)['status'], ('UNSUPPORTED_PLATFORM','UNVERIFIED','OBSERVED_NAMES_AND_SIZES_ONLY'))
    def test_extent_limit(self):
        self.assertEqual(sparse_extents(self.a,max_extents=0)['status'],'LIMIT_EXCEEDED')

if __name__=='__main__': unittest.main()
