import hashlib
import tempfile
import unittest
from pathlib import Path
from native_benchmark_stage_inventory import inventory_stages, cockpit_evidence_payload
from native_benchmark_authenticated import append_authenticated

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.keys = {'k': b'A'*32}
        self.journal = self.root/'journal'
        append_authenticated(self.journal, {'schema':'odmm.audit.mixed_benchmark.v1','status':'PASS',
            'cutover_authorized':False,'source_read_only':True,'isolated_copy':True},keys=self.keys,key_id='k')
    def test_empty(self):
        self.assertEqual(inventory_stages(self.root)['status'],'CLEAR')
    def test_stage_digest_preserved(self):
        p=self.root/'.odmm-stage-123';p.write_bytes(b'forensic')
        result=inventory_stages(self.root)
        self.assertEqual(result['entries'][0]['sha256'],hashlib.sha256(b'forensic').hexdigest())
        self.assertEqual(p.read_bytes(),b'forensic')
        self.assertFalse(result['cleanup_authorized'])
    def test_symlink_not_followed(self):
        outside=self.root/'outside';outside.write_bytes(b'secret')
        (self.root/'.odmm-stage-link').symlink_to(outside)
        self.assertEqual(inventory_stages(self.root)['entries'][0]['status'],'UNSAFE_TYPE')
    def test_directory_not_followed(self):
        (self.root/'.odmm-stage-dir').mkdir()
        self.assertEqual(inventory_stages(self.root)['entries'][0]['status'],'UNSAFE_TYPE')
    def test_parent_symlink_rejected(self):
        alias=self.root/'alias';alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):inventory_stages(alias)
    def test_oversize_rejected(self):
        p=self.root/'.odmm-stage-large'
        with p.open('wb') as f:f.truncate(20_000_001)
        self.assertEqual(inventory_stages(self.root)['entries'][0]['status'],'TOO_LARGE')
    def test_cockpit_review(self):
        (self.root/'.odmm-stage-a').write_bytes(b'partial')
        result=cockpit_evidence_payload(self.journal,self.root,keys=self.keys)
        self.assertEqual(result['status'],'REVIEW_REQUIRED')
        self.assertEqual(result['evidence']['status'],'VERIFIED')
        self.assertFalse(result['cutover_authorized'])
    def test_cockpit_blocked(self):
        with self.journal.open('ab') as f:f.write(b'partial')
        result=cockpit_evidence_payload(self.journal,self.root,keys=self.keys)
        self.assertEqual(result['status'],'BLOCKED')
        self.assertTrue(result['requires_human_review'])
    def test_missing_directory_blocks(self):
        result=cockpit_evidence_payload(self.journal,self.root/'missing',keys=self.keys)
        self.assertEqual(result['status'],'BLOCKED')
