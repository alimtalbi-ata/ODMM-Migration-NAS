"""V228.32: post-crash tampering must never silently acknowledge a migration."""
from test_native_incremental_crash_boundaries import CrashBoundaryTests
from native_posix_migration import MigrationBlocked

class CrashAdversarialTests(CrashBoundaryTests):
    def test_after_publish_changed_source_rejected(self):
        self.crash('AFTER_PUBLISH')
        (self.src/'new').write_bytes(b'changed-source')
        engine, planner, executor = self.reopen()
        try:
            with self.assertRaises(MigrationBlocked):
                engine.reconcile('new', operator_confirmed=True)
            with self.assertRaises(MigrationBlocked):
                executor.acknowledge_reconciled(self.plan, 'new', claim_token=self.token, operator_confirmed=True)
        finally: engine.close()

    def test_after_native_commit_stale_token_rejected(self):
        self.crash('AFTER_NATIVE_COMMIT')
        engine, planner, executor = self.reopen()
        try:
            with self.assertRaises(MigrationBlocked):
                executor.acknowledge_reconciled(self.plan, 'new', claim_token='obsolete-token', operator_confirmed=True)
            self.assertEqual(planner.inspect(self.plan)['tasks'][0]['status'], 'CLAIMED')
        finally: engine.close()

    def test_after_publish_ack_without_native_reconcile_refused(self):
        self.crash('AFTER_PUBLISH')
        engine, planner, executor = self.reopen()
        try:
            with self.assertRaises(MigrationBlocked):
                executor.acknowledge_reconciled(self.plan, 'new', claim_token=self.token, operator_confirmed=True)
            self.assertEqual(planner.inspect(self.plan)['tasks'][0]['status'], 'CLAIMED')
        finally: engine.close()
