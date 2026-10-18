import unittest
from native_migration_errors import MigrationBlocked
from native_audit_bridge import activate
from native_orphan_review import create_review, approve_for_manual_investigation
from native_segmented_audit import verify
from native_orphan_audit import verify as legacy_verify
from test_native_posix_migration import NativeMigrationTests

OLD=b'A'*32
NEW=b'C'*32

class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.t=NativeMigrationTests('test_copy_and_verify'); self.t.setUp()
        self.name='.odmm-'+'a'*32+'.part'
        (self.t.dst/self.name).write_bytes(b'temporary')
        self.engine=self.t.engine(); self.engine.__enter__()
        self.rid=create_review(self.engine)[0]['review_id']
    def tearDown(self):
        self.engine.__exit__(None,None,None); self.t.tearDown()
    def activate(self):
        return activate(self.engine,legacy_key=OLD,segment_key_id='k1',segment_key=NEW,operator='reviewer',rationale='Approved audit bridge rollout')
    def approve(self,**kw):
        return approve_for_manual_investigation(self.engine,self.rid,operator='reviewer',rationale='Inspect orphan without deleting',audit_key=OLD,**kw)
    def test_activation_checkpoint(self):
        self.activate()
        self.assertEqual(verify(self.engine.db,{'k1':NEW})['events'],1)
    def test_dual_write(self):
        self.activate(); self.approve(segment_keys={'k1':NEW})
        self.assertEqual(legacy_verify(self.engine.db,OLD)['events'],1)
        self.assertEqual(verify(self.engine.db,{'k1':NEW})['events'],2)
    def test_missing_segment_keys_rolls_back(self):
        self.activate()
        with self.assertRaises(MigrationBlocked): self.approve()
        self.assertEqual(legacy_verify(self.engine.db,OLD)['events'],0)
        self.assertEqual(self.engine.db.execute('SELECT state FROM orphan_reviews').fetchone()[0],'PENDING')
    def test_wrong_segment_key_rolls_back(self):
        self.activate()
        with self.assertRaises(MigrationBlocked): self.approve(segment_keys={'k1':b'D'*32})
        self.assertEqual(legacy_verify(self.engine.db,OLD)['events'],0)
    def test_repeat_activation_blocked(self):
        self.activate()
        with self.assertRaises(MigrationBlocked): self.activate()
    def test_checkpoint_tamper_blocks_decision(self):
        self.activate()
        self.engine.db.execute("UPDATE audit_bridge_state SET legacy_head='bad'")
        with self.assertRaises(MigrationBlocked): self.approve(segment_keys={'k1':NEW})
        self.assertEqual(legacy_verify(self.engine.db,OLD)['events'],0)
    def test_legacy_history_preserved(self):
        self.approve()
        self.activate()
        self.assertEqual(verify(self.engine.db,{'k1':NEW})['events'],1)
        self.assertEqual(legacy_verify(self.engine.db,OLD)['events'],1)

if __name__=='__main__': unittest.main()
