"""Actual SIGKILL-equivalent process exits across incremental transaction boundaries."""
import multiprocessing as mp
import os
import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked
from native_incremental_inventory import IncrementalInventory
from native_incremental_planner import IncrementalPlanner
from native_incremental_executor import IncrementalExecutor


def _worker(src, dst, db, plan, token, boundary):
    engine=NativePosixMigration(src,dst,db)
    try:
        executor=IncrementalExecutor(IncrementalPlanner(IncrementalInventory(engine)))
        if boundary=='BEFORE_EXECUTION': os._exit(79)
        if boundary=='AFTER_TEMP_SYNC':
            original=engine._copy_locked
            def wrapped(path, **kwargs):
                return original(path,after_temp_sync=lambda:os._exit(80),**kwargs)
            engine._copy_locked=wrapped
        if boundary=='AFTER_NATIVE_COMMIT':
            original=engine._copy_locked
            def wrapped(path,**kwargs):
                original(path,**kwargs)
                os._exit(81)
            engine._copy_locked=wrapped
        executor.execute_claimed(plan,'new',claim_token=token,
            after_publish=(lambda:os._exit(82)) if boundary=='AFTER_PUBLISH' else None)
        os._exit(0)
    finally:
        engine.close()

class CrashBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        root=Path(self.temp.name);self.src=root/'src';self.dst=root/'dst';self.db=root/'state.sqlite'
        self.src.mkdir();self.dst.mkdir()
        self.engine=NativePosixMigration(self.src,self.dst,self.db)
        inv=IncrementalInventory(self.engine);planner=IncrementalPlanner(inv)
        first=inv.capture()['pass_id'];(self.src/'new').write_bytes(b'data'*1024)
        second=inv.capture()['pass_id'];self.plan=planner.create(first,second)['plan_id']
        self.token=planner.claim_copy(self.plan,'new')['claim_token']
        self.engine.close()
    def tearDown(self):self.temp.cleanup()
    def reopen(self):
        engine=NativePosixMigration(self.src,self.dst,self.db)
        planner=IncrementalPlanner(IncrementalInventory(engine))
        return engine,planner,IncrementalExecutor(planner)
    def crash(self,boundary):
        ctx=mp.get_context('spawn')
        proc=ctx.Process(target=_worker,args=(self.src,self.dst,self.db,self.plan,self.token,boundary))
        proc.start();proc.join(12)
        if proc.is_alive():proc.kill();proc.join();self.fail('worker hung')
        self.assertEqual(proc.exitcode,{'BEFORE_EXECUTION':79,'AFTER_TEMP_SYNC':80,'AFTER_NATIVE_COMMIT':81,'AFTER_PUBLISH':82}[boundary])
    def test_crash_before_execution_claim_persists(self):
        self.crash('BEFORE_EXECUTION')
        engine,planner,executor=self.reopen()
        try:
            self.assertEqual(planner.inspect(self.plan)['tasks'][0]['status'],'CLAIMED')
            self.assertFalse((self.dst/'new').exists())
            self.assertEqual(executor.execute_claimed(self.plan,'new',claim_token=self.token)['status'],'VERIFIED_POSIX_SUBSET')
        finally:engine.close()
    def test_crash_after_temp_sync_safe_retry(self):
        self.crash('AFTER_TEMP_SYNC')
        engine,planner,executor=self.reopen()
        try:
            self.assertFalse((self.dst/'new').exists())
            self.assertEqual(executor.execute_claimed(self.plan,'new',claim_token=self.token)['status'],'VERIFIED_POSIX_SUBSET')
        finally:engine.close()
    def test_crash_after_publish_requires_review(self):
        self.crash('AFTER_PUBLISH')
        engine,planner,executor=self.reopen()
        try:
            self.assertEqual((self.dst/'new').read_bytes(),b'data'*1024)
            with self.assertRaises(MigrationBlocked):executor.execute_claimed(self.plan,'new',claim_token=self.token)
            with self.assertRaises(MigrationBlocked):executor.acknowledge_reconciled(self.plan,'new',claim_token=self.token,operator_confirmed=True)
            engine.reconcile('new',operator_confirmed=True)
            self.assertEqual(executor.acknowledge_reconciled(self.plan,'new',claim_token=self.token,operator_confirmed=True)['status'],'VERIFIED_POSIX_SUBSET')
        finally:engine.close()
    def test_crash_after_native_commit_requires_ack(self):
        self.crash('AFTER_NATIVE_COMMIT')
        engine,planner,executor=self.reopen()
        try:
            with self.assertRaises(MigrationBlocked):executor.execute_claimed(self.plan,'new',claim_token=self.token)
            self.assertEqual(executor.acknowledge_reconciled(self.plan,'new',claim_token=self.token,operator_confirmed=True)['status'],'VERIFIED_POSIX_SUBSET')
            with self.assertRaises(MigrationBlocked):executor.acknowledge_reconciled(self.plan,'new',claim_token=self.token,operator_confirmed=True)
        finally:engine.close()
    def test_crash_after_publish_changed_target_refused(self):
        self.crash('AFTER_PUBLISH')
        (self.dst/'new').write_bytes(b'corrupt')
        engine,planner,executor=self.reopen()
        try:
            with self.assertRaises(MigrationBlocked):engine.reconcile('new',operator_confirmed=True)
            with self.assertRaises(MigrationBlocked):executor.acknowledge_reconciled(self.plan,'new',claim_token=self.token,operator_confirmed=True)
        finally:engine.close()

if __name__=='__main__':unittest.main()
