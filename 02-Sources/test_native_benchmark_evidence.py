import tempfile
import unittest
from pathlib import Path
from native_benchmark_authenticated import append_authenticated
from native_benchmark_evidence import snapshot_evidence

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'journal';self.backup=Path(self.temp.name)/'backup'
        self.keys={'k1':b'A'*32}
        self.report={'schema':'odmm.audit.mixed_benchmark.v1','status':'PASS','error_count':0,'cutover_authorized':False,'source_read_only':True,'isolated_copy':True}
    def seed(self):append_authenticated(self.path,self.report,keys=self.keys,key_id='k1')
    def test_missing(self):
        self.assertEqual(snapshot_evidence(self.path,keys=self.keys)['status'],'EMPTY')
    def test_healthy_snapshot(self):
        self.seed(); r=snapshot_evidence(self.path,keys=self.keys,backup_path=self.backup)
        self.assertEqual(r['status'],'VERIFIED');self.assertEqual(self.path.read_bytes(),self.backup.read_bytes())
        self.assertFalse(r['cutover_authorized'])
    def test_broken_tail_backup(self):
        self.seed();
        with self.path.open('ab') as stream:stream.write(b'{broken')
        r=snapshot_evidence(self.path,keys=self.keys,backup_path=self.backup)
        self.assertEqual(r['status'],'BLOCKED');self.assertEqual(self.path.read_bytes(),self.backup.read_bytes())
    def test_wrong_key(self):
        self.seed();self.assertEqual(snapshot_evidence(self.path,keys={'k1':b'B'*32})['status'],'BLOCKED')
    def test_existing_backup_preserved(self):
        self.seed();self.backup.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):snapshot_evidence(self.path,keys=self.keys,backup_path=self.backup)
        self.assertEqual(self.backup.read_bytes(),b'keep')
    def test_source_same_destination_refused(self):
        self.seed();before=self.path.read_bytes()
        with self.assertRaises(ValueError):snapshot_evidence(self.path,keys=self.keys,backup_path=self.path)
        self.assertEqual(before,self.path.read_bytes())
    def test_snapshot_no_mutation(self):
        self.seed();before=self.path.read_bytes();snapshot_evidence(self.path,keys=self.keys)
        self.assertEqual(before,self.path.read_bytes())

if __name__=='__main__':unittest.main()

class HardenedEvidenceTests(EvidenceTests):
    def test_symlink_parent_rejected(self):
        self.seed()
        target=Path(self.temp.name)/'real';target.mkdir()
        link=Path(self.temp.name)/'linked';link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            snapshot_evidence(self.path,keys=self.keys,backup_path=link/'copy')
        self.assertFalse((target/'copy').exists())

    def test_backup_mode_private(self):
        self.seed();snapshot_evidence(self.path,keys=self.keys,backup_path=self.backup)
        self.assertEqual(self.backup.stat().st_mode & 0o777,0o600)
