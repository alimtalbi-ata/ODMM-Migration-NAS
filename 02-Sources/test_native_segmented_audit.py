import sqlite3
import unittest
from native_segmented_audit import initialize,start,append,rotate,verify,anchor
from native_migration_errors import MigrationBlocked

A=b'a'*32
B=b'b'*32

class SegmentedAuditTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:')
        initialize(self.db)
        start(self.db,'k1',A)
        self.keys={'k1':A}
    def tearDown(self): self.db.close()
    def rotate(self):
        rotate(self.db,self.keys,'k2',B)
        self.keys['k2']=B
    def test_empty(self): self.assertEqual(verify(self.db,self.keys)['events'],0)
    def test_append(self):
        append(self.db,self.keys,{'a':1})
        self.assertEqual(verify(self.db,self.keys)['events'],1)
    def test_rotate(self):
        append(self.db,self.keys,{'a':1}); self.rotate(); append(self.db,self.keys,{'b':2})
        self.assertEqual(verify(self.db,self.keys)['segments'],2)
    def test_wrong_old_key(self):
        self.rotate()
        with self.assertRaises(MigrationBlocked): verify(self.db,{'k1':B,'k2':B})
    def test_wrong_new_key(self):
        self.rotate()
        with self.assertRaises(MigrationBlocked): verify(self.db,{'k1':A,'k2':A})
    def test_event_tamper(self):
        append(self.db,self.keys,{'a':1}); self.db.execute("UPDATE audit_segment_events SET event='{}'")
        with self.assertRaises(MigrationBlocked): verify(self.db,self.keys)
    def test_boundary_tamper(self):
        self.rotate(); self.db.execute("UPDATE audit_segments SET boundary_old_mac='bad' WHERE segment=2")
        with self.assertRaises(MigrationBlocked): verify(self.db,self.keys)
    def test_truncated_event(self):
        append(self.db,self.keys,{'a':1}); self.db.execute('DELETE FROM audit_segment_events')
        with self.assertRaises(MigrationBlocked): verify(self.db,self.keys)
    def test_external_anchor(self):
        append(self.db,self.keys,{'a':1}); cp=anchor(self.db,self.keys)
        self.assertEqual(verify(self.db,self.keys,trusted_anchor=cp)['events'],1)
        self.rotate()
        with self.assertRaises(MigrationBlocked): verify(self.db,self.keys,trusted_anchor=cp)
    def test_reuse_key_id_blocked(self):
        with self.assertRaises(MigrationBlocked): rotate(self.db,self.keys,'k1',B)
    def test_identical_key_blocked(self):
        with self.assertRaises(MigrationBlocked): rotate(self.db,self.keys,'k2',A)
    def test_missing_key_blocked(self):
        self.rotate()
        with self.assertRaises(MigrationBlocked): verify(self.db,{'k2':B})
    def test_rollback_rotation(self):
        self.db.commit(); self.db.execute('BEGIN IMMEDIATE'); self.rotate(); self.db.rollback()
        self.assertEqual(verify(self.db,{'k1':A})['segments'],1)
    def test_no_cutover(self): self.assertFalse(verify(self.db,self.keys)['cutover_authorized'])

if __name__=='__main__': unittest.main()
