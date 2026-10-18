import concurrent.futures
import tempfile
import unittest
from pathlib import Path
from native_benchmark_authenticated import append_authenticated
from native_benchmark_evidence import snapshot_evidence

class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.journal=self.base/'journal';self.target=self.base/'evidence'
        self.keys={'key':b'A'*32}
        report={'schema':'odmm.audit.mixed_benchmark.v1','status':'PASS','cutover_authorized':False,'source_read_only':True,'isolated_copy':True}
        append_authenticated(self.journal,report,keys=self.keys,key_id='key')
    def save(self):return snapshot_evidence(self.journal,keys=self.keys,backup_path=self.target)
    def test_no_stage_on_success(self):
        self.assertTrue(self.save()['backup_created'])
        self.assertEqual(self.target.read_bytes(),self.journal.read_bytes())
        self.assertFalse(list(self.base.glob('.odmm-stage-*')))
    def test_existing_target_untouched(self):
        self.target.write_bytes(b'original')
        with self.assertRaises(FileExistsError):self.save()
        self.assertEqual(self.target.read_bytes(),b'original')
        self.assertFalse(list(self.base.glob('.odmm-stage-*')))
    def test_parallel_publication_one_winner(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures=[pool.submit(self.save) for _ in range(8)]
            outcomes=[]
            for f in futures:
                try:outcomes.append(f.result()['backup_created'])
                except FileExistsError:outcomes.append(False)
        self.assertEqual(outcomes.count(True),1)
        self.assertEqual(self.target.read_bytes(),self.journal.read_bytes())
        self.assertFalse(list(self.base.glob('.odmm-stage-*')))
    def test_symlink_destination_not_followed(self):
        original=self.base/'original';original.write_bytes(b'preserved')
        self.target.symlink_to(original)
        with self.assertRaises(FileExistsError):self.save()
        self.assertEqual(original.read_bytes(),b'preserved')
    def test_blocked_journal_preserved(self):
        with self.journal.open('ab') as f:f.write(b'incomplete')
        result=self.save()
        self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(self.target.read_bytes(),self.journal.read_bytes())
