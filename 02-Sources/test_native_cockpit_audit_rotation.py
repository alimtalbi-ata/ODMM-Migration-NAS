import copy
import tempfile
import unittest
from pathlib import Path
from native_benchmark_cockpit_adapter import _audit, GENESIS
from native_cockpit_audit_operations import verify_access_audit
from native_cockpit_audit_rotation import prepare_rotation, verify_rotation

OLD=b'o'*32
NEW=b'n'*32

class RotationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'audit.sqlite'
        _audit(self.db,'alice','evidence.read.json','ALLOW','a'*64,OLD)
        self.head=verify_access_audit(self.db,audit_key=OLD)['head_sha256']
        self.kw=dict(old_key=OLD,new_key=NEW,old_key_id='epoch-1',new_key_id='epoch-2',
                     checkpoint_count=1,checkpoint_head=self.head,request_id='request-0001')
    def proposal(self): return prepare_rotation(self.db,**self.kw)
    def test_valid(self):
        self.assertEqual(verify_rotation(self.proposal(),old_key=OLD,new_key=NEW,
                         expected_request_id='request-0001')['status'],'VERIFIED_PENDING_APPROVAL')
    def test_old_key_wrong(self):
        with self.assertRaises(ValueError): self.proposal_wrong(old_key=b'z'*32)
    def proposal_wrong(self,**overrides):
        return prepare_rotation(self.db,**{**self.kw,**overrides})
    def test_new_key_reused(self):
        with self.assertRaises(ValueError): self.proposal_wrong(new_key=OLD)
    def test_same_key_id(self):
        with self.assertRaises(ValueError): self.proposal_wrong(new_key_id='epoch-1')
    def test_checkpoint_rollback(self):
        with self.assertRaises(ValueError): self.proposal_wrong(checkpoint_count=2)
    def test_bad_checkpoint(self):
        with self.assertRaises(ValueError): self.proposal_wrong(checkpoint_head='0'*64)
    def test_tamper(self):
        p=self.proposal();p['payload']['current_head']='f'*64
        with self.assertRaises(ValueError): verify_rotation(p,old_key=OLD,new_key=NEW,expected_request_id='request-0001')
    def test_wrong_new_key(self):
        with self.assertRaises(ValueError): verify_rotation(self.proposal(),old_key=OLD,new_key=b'x'*32,expected_request_id='request-0001')
    def test_replay(self):
        with self.assertRaises(ValueError): verify_rotation(self.proposal(),old_key=OLD,new_key=NEW,expected_request_id='request-0002')
    def test_head_pin(self):
        with self.assertRaises(ValueError): verify_rotation(self.proposal(),old_key=OLD,new_key=NEW,expected_request_id='request-0001',expected_current_head='0'*64)
    def test_no_mutation(self):
        before=self.db.read_bytes();self.proposal();self.assertEqual(before,self.db.read_bytes())
    def test_short_key(self):
        with self.assertRaises(ValueError): self.proposal_wrong(new_key=b'short')
