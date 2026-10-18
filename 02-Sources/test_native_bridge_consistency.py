import unittest
from native_bridge_consistency import verify_bridge
from native_migration_errors import MigrationBlocked
from native_segmented_audit import rotate, append, verify
from test_native_audit_bridge import BridgeTests, OLD, NEW

class ConsistencyTests(BridgeTests):
    def setUp(self): super().setUp()
    def check(self, **kw):
        return verify_bridge(self.engine.db,legacy_key=OLD,segment_keys={'k1':NEW},**kw)
    def test_empty_bridge(self):
        self.activate(); self.assertEqual(self.check()['linked_decisions'],0)
    def test_one_decision(self):
        self.activate(); self.approve(segment_keys={'k1':NEW}); self.assertEqual(self.check()['linked_decisions'],1)
    def test_restart(self):
        self.activate(); self.approve(segment_keys={'k1':NEW})
        self.engine.__exit__(None,None,None)
        self.engine=self.t.engine(); self.engine.__enter__()
        self.assertEqual(self.check()['linked_decisions'],1)
    def test_missing_segment_decision_detected(self):
        self.activate(); self.approve(segment_keys={'k1':NEW})
        self.engine.db.execute('DELETE FROM audit_segment_events WHERE segment=1 AND seq=2')
        with self.assertRaises(MigrationBlocked): self.check()
    def test_extra_segment_decision_detected(self):
        self.activate(); append(self.engine.db,{'k1':NEW},{'kind':'ORPHAN_REVIEW_DECISION','legacy_sequence':42,'legacy_head':'x','decision':{}})
        with self.assertRaises(MigrationBlocked): self.check()
    def test_legacy_truncation_detected_with_anchor(self):
        self.activate(); self.approve(segment_keys={'k1':NEW})
        from native_orphan_audit import verify as legacy_verify
        anchor=legacy_verify(self.engine.db,OLD)
        self.engine.db.execute('DELETE FROM orphan_audit_chain')
        with self.assertRaises(MigrationBlocked): self.check(trusted_legacy=anchor)
    def test_wrong_checkpoint(self):
        self.activate(); self.engine.db.execute('UPDATE audit_bridge_state SET legacy_head=?',('f'*64,))
        with self.assertRaises(MigrationBlocked): self.check()
    def test_external_segment_anchor(self):
        self.activate(); self.approve(segment_keys={'k1':NEW})
        anchor={'segment':1,'events':2,'head':verify(self.engine.db,{'k1':NEW})['head']}
        self.assertEqual(self.check(trusted_segment=anchor)['linked_decisions'],1)
    def test_wrong_external_anchor(self):
        self.activate()
        with self.assertRaises(MigrationBlocked): self.check(trusted_segment={'segment':1,'events':999,'head':'x'})

if __name__=='__main__': unittest.main()
