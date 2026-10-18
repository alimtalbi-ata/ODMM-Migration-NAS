import sqlite3
import tempfile
import unittest
from pathlib import Path
from native_cockpit_audit_epochs import transact_epoch, seal_rotation_apis, verify_epochs
from native_rotation_unified_gate import rotate_with_sealed_governance

class SealTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'test.db'
        self.keys={'a':b'a'*32,'b':b'b'*32}
        self.start=transact_epoch(self.db,keys=self.keys,operation='START',key_id='a')
    def test_seal_is_explicit(self):
        self.assertTrue(seal_rotation_apis(self.db,keys=self.keys)['sealed'])
    def test_seal_idempotent(self):
        seal_rotation_apis(self.db,keys=self.keys)
        self.assertTrue(seal_rotation_apis(self.db,keys=self.keys)['sealed'])
    def test_legacy_rotation_refused(self):
        seal_rotation_apis(self.db,keys=self.keys)
        with self.assertRaisesRegex(ValueError,'LEGACY_ROTATION_SEALED'):
            transact_epoch(self.db,keys=self.keys,operation='ROTATE',key_id='b',expected_head=self.start['head'])
        self.assertEqual('a',verify_epochs(self.db,keys=self.keys)['active_key_id'])
    def test_events_still_allowed(self):
        seal_rotation_apis(self.db,keys=self.keys)
        self.assertEqual(2,transact_epoch(self.db,keys=self.keys,operation='EVENT',event_digest='f'*64)['count'])
    def test_unsealed_entrypoint_refused(self):
        with self.assertRaisesRegex(ValueError,'ROTATION_SEAL_REQUIRED'):
            rotate_with_sealed_governance(self.db)
    def test_seal_rollback_in_transaction(self):
        with self.assertRaises(ValueError):seal_rotation_apis(self.db,keys={'a':b'c'*32,'b':b'b'*32})
        with sqlite3.connect(self.db) as conn:
            self.assertFalse(conn.execute("SELECT 1 FROM sqlite_master WHERE name='epoch_rotation_seal'").fetchone())
    def test_legacy_rotation_unsealed_remains_compatible(self):
        self.assertTrue(transact_epoch(self.db,keys=self.keys,operation='ROTATE',key_id='b',expected_head=self.start['head'])['rotation_applied'])
