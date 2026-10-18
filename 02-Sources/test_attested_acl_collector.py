import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from types import SimpleNamespace
from attested_acl_collector import collect_attested_acl, AttestedCollectionError

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); (self.root/'data').write_text('hello')
        self.mi=lambda fs='nfs4',source='nas:/vol': f'20 1 0:42 / {self.root} rw,vers=4.1 - {fs} {source} rw\n'
        self.kw=dict(root=self.root,relative_path='data',protocol='NFSv4',side='source',collector_id='collector1',identity_context='test',runner=lambda argv:SimpleNamespace(returncode=0,stdout=b'ACL data'))
    def test_valid_mount(self):
        result=collect_attested_acl(**self.kw,mountinfo_reader=lambda:self.mi())
        self.assertEqual(result['mount_attestation']['fstype'],'nfs4')
    def test_wrong_mount(self):
        with self.assertRaises(AttestedCollectionError): collect_attested_acl(**self.kw,mountinfo_reader=lambda:self.mi('ext4'))
    def test_mount_swap(self):
        reads=iter([self.mi(),self.mi(source='other:/vol')])
        with self.assertRaises(AttestedCollectionError): collect_attested_acl(**self.kw,mountinfo_reader=lambda:next(reads))
    def test_missing_mount(self):
        with self.assertRaises(AttestedCollectionError): collect_attested_acl(**self.kw,mountinfo_reader=lambda:'')
    def test_tool_failure(self):
        kw=dict(self.kw); kw['runner']=lambda argv:SimpleNamespace(returncode=1,stdout=b'')
        with self.assertRaises(AttestedCollectionError): collect_attested_acl(**kw,mountinfo_reader=lambda:self.mi())
    def test_symlink(self):
        (self.root/'link').symlink_to(self.root/'data'); kw=dict(self.kw);kw['relative_path']='link'
        with self.assertRaises(AttestedCollectionError): collect_attested_acl(**kw,mountinfo_reader=lambda:self.mi())

if __name__=='__main__':unittest.main()
