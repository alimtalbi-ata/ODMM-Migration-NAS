import sqlite3
import unittest
from pathlib import Path
from native_bridge_consistency import verify_bridge_snapshot
from native_migration_errors import MigrationBlocked
from test_native_audit_bridge import BridgeTests, OLD, NEW


class SnapshotTests(BridgeTests):
    def dbpath(self):
        row = self.engine.db.execute('PRAGMA database_list').fetchall()
        return next(Path(x[2]) for x in row if x[1] == 'main')

    def check_snapshot(self, **kw):
        return verify_bridge_snapshot(self.dbpath(), legacy_key=OLD,
                                      segment_keys={'k1': NEW}, **kw)

    def test_empty_checkpoint(self):
        self.activate()
        self.assertEqual(self.check_snapshot()['linked_decisions'], 0)

    def test_committed_decision(self):
        self.activate(); self.approve(segment_keys={'k1': NEW})
        self.assertEqual(self.check_snapshot()['linked_decisions'], 1)

    def test_uncommitted_changes_not_visible(self):
        self.activate()
        self.engine.db.execute('BEGIN IMMEDIATE')
        try:
            self.engine.db.execute("UPDATE audit_bridge_state SET legacy_head='corrupted'")
            self.assertEqual(self.check_snapshot()['status'], 'CONSISTENT')
        finally:
            self.engine.db.execute('ROLLBACK')

    def test_committed_corruption_detected(self):
        self.activate()
        self.engine.db.execute("UPDATE audit_bridge_state SET legacy_head='corrupted'")
        with self.assertRaises(MigrationBlocked):
            self.check_snapshot()

    def test_readonly_no_schema_mutation(self):
        self.activate()
        before = self.engine.db.execute("SELECT name FROM sqlite_master ORDER BY name").fetchall()
        self.check_snapshot()
        self.assertEqual(before, self.engine.db.execute("SELECT name FROM sqlite_master ORDER BY name").fetchall())

    def test_missing_database_does_not_create(self):
        missing = self.dbpath().with_name('does-not-exist.db')
        with self.assertRaises(MigrationBlocked):
            verify_bridge_snapshot(missing, legacy_key=OLD, segment_keys={'k1':NEW})
        self.assertFalse(missing.exists())

if __name__ == '__main__':
    unittest.main()
