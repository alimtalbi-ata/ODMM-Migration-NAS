"""V228.31: real process termination on either side of SQLite COMMIT."""
import copy
import hashlib
import multiprocessing as mp
import os
import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked
from native_incremental_inventory import IncrementalInventory
from native_incremental_planner import IncrementalPlanner, canonical


def crash_worker(src, dst, database, plan, boundary):
    engine = NativePosixMigration(src, dst, database)
    db = engine.db
    db.execute('BEGIN IMMEDIATE')
    db.execute("UPDATE incremental_tasks SET status='CLAIMED',claim_token='worker-token',claimed_ns=1 WHERE plan_id=? AND path='file' AND status='PENDING'", (plan,))
    if boundary == 'BEFORE_COMMIT':
        os._exit(91)
    db.execute('COMMIT')
    os._exit(92)


def publish_crash_worker(src, dst, database):
    """Hard-exit after target publication and durable intent, before ledger commit."""
    engine = NativePosixMigration(src, dst, database)
    engine.copy('file', after_publish=lambda: os._exit(93))
    os._exit(94)


class SqliteCommitCrashTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.src, self.dst, self.database = root/'src', root/'dst', root/'registry.sqlite'
        self.src.mkdir(); self.dst.mkdir()
        engine = NativePosixMigration(self.src, self.dst, self.database)
        inv = IncrementalInventory(engine)
        before = inv.capture()['pass_id']
        (self.src/'file').write_bytes(b'content')
        after = inv.capture()['pass_id']
        self.plan = IncrementalPlanner(inv).create(before, after)['plan_id']
        engine.close()

    def tearDown(self):
        self.temp.cleanup()

    def run_boundary(self, boundary, expected_status, expected_token):
        process = mp.get_context('spawn').Process(target=crash_worker, args=(self.src,self.dst,self.database,self.plan,boundary))
        process.start(); process.join(15)
        if process.is_alive():
            process.kill(); process.join(); self.fail('crash worker timed out')
        self.assertEqual(process.exitcode, 91 if boundary == 'BEFORE_COMMIT' else 92)
        engine = NativePosixMigration(self.src, self.dst, self.database)
        try:
            planner = IncrementalPlanner(IncrementalInventory(engine))
            row = engine.db.execute('SELECT status,claim_token FROM incremental_tasks WHERE plan_id=? AND path=?',(self.plan,'file')).fetchone()
            self.assertEqual(row, (expected_status, expected_token))
            self.assertFalse((self.dst/'file').exists())
            self.assertEqual(engine.db.execute('SELECT COUNT(*) FROM files').fetchone()[0], 0)
            self.assertEqual(engine.db.execute('SELECT COUNT(*) FROM intents').fetchone()[0], 0)
            self.assertEqual(engine.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            audit = planner.recovery_audit(self.plan)
            self.assertTrue(planner.verify_recovery_audit(audit))
            tampered = copy.deepcopy(audit)
            tampered['tasks'][0]['status'] = 'FORGED'
            self.assertFalse(planner.verify_recovery_audit(tampered))
            tampered = copy.deepcopy(audit)
            tampered['cutover_authorized'] = True
            self.assertFalse(planner.verify_recovery_audit(tampered))
            self.assertFalse(planner.verify_recovery_audit({'sha256': audit['sha256']}))
            digest = audit['sha256']
            self.assertEqual(
                digest,
                hashlib.sha256(canonical({k: v for k, v in audit.items() if k != 'sha256'})).hexdigest()
            )
            self.assertEqual(audit['evidence_scope'], 'sqlite_registry_observation_only')
            self.assertFalse(audit['cutover_authorized'])
            self.assertFalse(audit['automatic_reset'])
            recovery = planner.recovery_report(self.plan)
            self.assertTrue(recovery['read_only'])
            self.assertFalse(recovery['automatic_reset'])
            self.assertFalse(recovery['cutover_authorized'])
            self.assertEqual(recovery['tasks'][0]['decision'],
                             'CLAIM_ELIGIBLE' if boundary == 'BEFORE_COMMIT'
                             else 'OPERATOR_RESET_ELIGIBLE')
            self.assertEqual(
                recovery['tasks'][0]['recommended_next_step'],
                'RECHECK_THEN_CLAIM' if boundary == 'BEFORE_COMMIT'
                else 'RECHECK_THEN_EXPLICIT_OPERATOR_RESET'
            )
            self.assertFalse(recovery['tasks'][0]['native_intent'])
            self.assertFalse(recovery['tasks'][0]['native_file_record'])
            if boundary == 'BEFORE_COMMIT':
                self.assertEqual(planner.claim_copy(self.plan,'file')['status'],'CLAIMED_NOT_EXECUTED')
            else:
                with self.assertRaises(MigrationBlocked): planner.claim_copy(self.plan,'file')
                persisted = engine.db.execute(
                    'SELECT status,claim_token FROM incremental_tasks WHERE plan_id=? AND path=?',
                    (self.plan, 'file')
                ).fetchone()
                self.assertEqual(persisted, ('CLAIMED', 'worker-token'))
        finally:
            engine.close()


    def test_kill_after_publish_requires_explicit_reconciliation(self):
        process = mp.get_context('spawn').Process(
            target=publish_crash_worker, args=(self.src, self.dst, self.database))
        process.start()
        process.join(15)
        if process.is_alive():
            process.kill()
            process.join()
            self.fail('publish crash worker timed out')
        self.assertEqual(process.exitcode, 93)
        self.assertEqual((self.dst / 'file').read_bytes(), b'content')
        engine = NativePosixMigration(self.src, self.dst, self.database)
        try:
            self.assertEqual(engine.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(engine.db.execute('SELECT COUNT(*) FROM intents').fetchone()[0], 1)
            self.assertEqual(engine.db.execute('SELECT COUNT(*) FROM files').fetchone()[0], 0)
            with self.assertRaises(MigrationBlocked):
                engine.copy('file')
            with self.assertRaises(MigrationBlocked):
                engine.reconcile('file')
            result = engine.reconcile('file', operator_confirmed=True)
            self.assertEqual(result['status'], 'RECONCILED_VERIFIED')
            self.assertFalse(result['cutover_authorized'])
            self.assertEqual(engine.db.execute('SELECT COUNT(*) FROM intents').fetchone()[0], 0)
            self.assertEqual(engine.verify('file')['status'], 'VERIFIED_POSIX_SUBSET_ONLY')
        finally:
            engine.close()

    def test_kill_before_commit_rollback_on_reopen(self):
        self.run_boundary('BEFORE_COMMIT', 'PENDING', None)

    def test_kill_after_commit_claim_persists(self):
        self.run_boundary('AFTER_COMMIT', 'CLAIMED', 'worker-token')

if __name__ == '__main__': unittest.main()
