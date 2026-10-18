"""V191.3: cross-process WAL snapshot and atomic writer isolation tests."""
import multiprocessing as mp
import sqlite3
import tempfile
import unittest
from pathlib import Path

from native_audit_bridge import activate
from native_bridge_consistency import verify_bridge_snapshot
from native_orphan_review import approve_for_manual_investigation, create_review
from native_segmented_audit import rotate
from test_native_audit_bridge import BridgeTests, OLD, NEW


def _writer(db_path, root_src, root_dst, review_id, ready, release, queue):
    try:
        from native_posix_migration import NativePosixMigration
        from native_orphan_review import approve_for_manual_investigation
        with NativePosixMigration(root_src, root_dst, db_path) as engine:
            # Make an uncommitted, but otherwise valid, dual-ledger write.
            engine.db.execute('BEGIN IMMEDIATE')
            try:
                # An uncommitted metadata write must never become visible to a reader.
                engine.db.execute("UPDATE audit_bridge_state SET legacy_head='uncommitted'")
                ready.set()
                if not release.wait(8):
                    raise RuntimeError('writer release timed out')
                engine.db.execute('ROLLBACK')
                queue.put('ROLLED_BACK')
            except BaseException:
                if engine.db.in_transaction:
                    engine.db.execute('ROLLBACK')
                raise
    except BaseException as exc:
        ready.set()
        queue.put('ERROR:'+repr(exc))


class MultiprocessAuditTests(BridgeTests):
    def test_snapshot_isolated_from_other_process_uncommitted_write(self):
        self.activate()
        ctx=mp.get_context('spawn')
        ready=ctx.Event(); release=ctx.Event(); queue=ctx.Queue()
        process=ctx.Process(target=_writer,args=(str(self.t.db),str(self.t.src),str(self.t.dst),self.rid,ready,release,queue))
        process.start()
        try:
            self.assertTrue(ready.wait(10))
            result=verify_bridge_snapshot(self.t.db,legacy_key=OLD,segment_keys={'k1':NEW})
            self.assertEqual(result['status'],'CONSISTENT')
            self.assertEqual(result['linked_decisions'],0)
        finally:
            release.set(); process.join(12)
            if process.is_alive(): process.terminate(); process.join()
        self.assertEqual(process.exitcode,0)
        self.assertEqual(queue.get(timeout=2),'ROLLED_BACK')

    def test_snapshot_with_committed_decision(self):
        self.activate()
        self.approve(segment_keys={'k1':NEW})
        result=verify_bridge_snapshot(self.t.db,legacy_key=OLD,segment_keys={'k1':NEW})
        self.assertEqual(result['linked_decisions'],1)
        self.assertFalse(result['cutover_authorized'])

    def test_snapshot_handles_database_filename_with_query_characters(self):
        self.activate()
        path=Path(self.t.db)
        # Copy a consistent SQLite image, not just its WAL-dependent main file.
        other=path.with_name('audit?fragment#check.db')
        with sqlite3.connect(other) as copy:
            self.engine.db.backup(copy)
        result=verify_bridge_snapshot(other,legacy_key=OLD,segment_keys={'k1':NEW})
        self.assertEqual(result['status'],'CONSISTENT')

if __name__=='__main__': unittest.main()
