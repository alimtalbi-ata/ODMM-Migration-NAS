import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from native_cockpit_audit_epochs import transact_epoch,verify_epochs

class EpochAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.db=Path(self.temp.name)/'audit.sqlite'
        self.keys={'a':b'A'*32,'b':b'B'*32}
        self.start=transact_epoch(self.db,keys=self.keys,operation='START',key_id='a')
    def test_rotation_preserves_old_events(self):
        a=transact_epoch(self.db,keys=self.keys,operation='EVENT',event_digest='a'*64)
        b=transact_epoch(self.db,keys=self.keys,operation='ROTATE',key_id='b',expected_head=a['head'])
        transact_epoch(self.db,keys=self.keys,operation='EVENT',event_digest='b'*64)
        result=verify_epochs(self.db,keys=self.keys,checkpoint={'count':a['count'],'head':a['head']})
        self.assertEqual((result['count'],result['active_key_id']),(4,'b'))
        self.assertTrue(b['rotation_applied'])
    def test_old_key_required(self):
        with self.assertRaises(ValueError):verify_epochs(self.db,keys={'b':self.keys['b']})
    def test_wrong_key(self):
        with self.assertRaises(ValueError):verify_epochs(self.db,keys={'a':b'X'*32})
    def test_tamper(self):
        with sqlite3.connect(self.db) as c:c.execute("UPDATE epoch_audit SET detail='evil' WHERE seq=1")
        with self.assertRaises(ValueError):verify_epochs(self.db,keys=self.keys)
    def test_rollback(self):
        with self.assertRaisesRegex(ValueError,'ROLLBACK'):verify_epochs(self.db,keys=self.keys,checkpoint={'count':2,'head':'0'*64})
    def test_wrong_checkpoint(self):
        with self.assertRaisesRegex(ValueError,'CHECKPOINT'):verify_epochs(self.db,keys=self.keys,checkpoint={'count':1,'head':'0'*64})
    def test_stale_rotation(self):
        with self.assertRaisesRegex(ValueError,'HEAD_CHANGED'):transact_epoch(self.db,keys=self.keys,operation='ROTATE',key_id='b',expected_head='0'*64)
    def test_no_reuse(self):
        with self.assertRaises(ValueError):transact_epoch(self.db,keys={'a':b'A'*32,'b':b'A'*32},operation='ROTATE',key_id='b',expected_head=self.start['head'])
    def test_invalid_event(self):
        with self.assertRaises(ValueError):transact_epoch(self.db,keys=self.keys,operation='EVENT',event_digest='not-a-digest')
    def test_duplicate_start(self):
        with self.assertRaises(ValueError):transact_epoch(self.db,keys=self.keys,operation='START',key_id='a')
    def test_invalid_key(self):
        with self.assertRaises(ValueError):transact_epoch(self.db,keys={'a':b'weak'},operation='EVENT',event_digest='a'*64)
    def test_read_only_verify(self):
        before=self.db.read_bytes();verify_epochs(self.db,keys=self.keys);self.assertEqual(before,self.db.read_bytes())
