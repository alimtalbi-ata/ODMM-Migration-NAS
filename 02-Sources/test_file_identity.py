import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from types import SimpleNamespace
from attested_acl_collector import collect_attested_acl, AttestedCollectionError

class FileIdentityTests(unittest.TestCase):
    def setUp(self):
        self.t=TemporaryDirectory();self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name);self.target=self.root/'file';self.target.write_text('data');self.target.chmod(0o644)
        self.mi=lambda:f'20 1 0:42 / {self.root} rw,vers=4.1 - nfs4 nas:/vol rw\n'
    def collect(self, runner):
        return collect_attested_acl(self.root,'file','NFSv4','source','collector','test',runner=runner,mountinfo_reader=self.mi)
    def test_unchanged(self):
        result=self.collect(lambda argv:SimpleNamespace(returncode=0,stdout=b'ACL'))
        self.assertIn('inode',result['path_identity'])
    def test_replaced_file_detected(self):
        def runner(argv):
            tmp=self.root/'replacement';tmp.write_text('different');tmp.replace(self.target)
            return SimpleNamespace(returncode=0,stdout=b'ACL')
        with self.assertRaisesRegex(AttestedCollectionError,'identity'):
            self.collect(runner)
    def test_mode_changed_detected(self):
        def runner(argv):
            self.target.chmod(0o600)
            return SimpleNamespace(returncode=0,stdout=b'ACL')
        with self.assertRaisesRegex(AttestedCollectionError,'mode'):
            self.collect(runner)
    def test_symlink_swap_rejected(self):
        def runner(argv):
            self.target.unlink();self.target.symlink_to(self.root/'elsewhere')
            return SimpleNamespace(returncode=0,stdout=b'ACL')
        with self.assertRaises(AttestedCollectionError):self.collect(runner)

if __name__=='__main__':unittest.main()
