import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_observation_hardened import observe_file

class HardenedObservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.file=Path(self.tmp.name)/'proof'; self.file.write_bytes(b'proof')
    def test_digest(self):
        result=observe_file(self.file)
        self.assertEqual(result['sha256'],hashlib.sha256(b'proof').hexdigest())
    def test_no_automatic_actions(self):
        result=observe_file(self.file)
        self.assertTrue(result['manual_review_required'])
        for key in ('cutover_authorized','recovery_authorized','publication_authorized'):
            self.assertFalse(result[key])
    def test_symlink_refused(self):
        link=Path(self.tmp.name)/'link'; link.symlink_to(self.file)
        with self.assertRaises(IdentityPinError):observe_file(link)
    def test_missing_file(self):
        with self.assertRaises(IdentityPinError):observe_file(self.file.parent/'missing')
    def test_relative_path(self):
        with self.assertRaises(IdentityPinError):observe_file('relative')
    def test_directory_refused(self):
        with self.assertRaises(IdentityPinError):observe_file(self.file.parent)
    def test_oversized(self):
        self.file.write_bytes(b'x'*1025)
        with self.assertRaises(IdentityPinError):observe_file(self.file,max_bytes=1024)
    def test_exact_boundary(self):
        self.file.write_bytes(b'x'*1024)
        self.assertEqual(observe_file(self.file,max_bytes=1024)['size'],1024)
    def test_mutation_between_stat_and_read(self):
        def mutate():self.file.write_bytes(b'changed')
        with self.assertRaises(IdentityPinError):observe_file(self.file,read_hook=mutate)
    def test_atomic_replacement_detected_as_old_inode(self):
        def replace():
            newer=self.file.parent/'new';newer.write_bytes(b'other');os.replace(newer,self.file)
        with self.assertRaises(IdentityPinError):observe_file(self.file,read_hook=replace)
    def test_invalid_limit(self):
        for limit in (0,-1,True,1024*1024+1,1.2):
            with self.subTest(limit=limit),self.assertRaises(IdentityPinError):observe_file(self.file,max_bytes=limit)
    def test_fifo_refused_without_blocking(self):
        fifo=self.file.parent/'fifo';os.mkfifo(fifo)
        with self.assertRaises(IdentityPinError):observe_file(fifo)

if __name__=='__main__':unittest.main()
