"""Multiprocess and restart qualification against the real native SQLite engine."""
import multiprocessing as mp
import tempfile
import unittest
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked
from native_incremental_inventory import IncrementalInventory
from native_incremental_planner import IncrementalPlanner
from native_incremental_executor import IncrementalExecutor


def attempt_claim(src, dst, db, plan, path, start, queue):
    engine = None
    try:
        engine = NativePosixMigration(Path(src), Path(dst), Path(db))
        planner = IncrementalPlanner(IncrementalInventory(engine))
        start.wait(15)
        try:
            result = planner.claim_copy(plan, path)
            queue.put(('CLAIMED', result['claim_token']))
        except MigrationBlocked as exc:
            queue.put(('BLOCKED', str(exc)))
    except BaseException as exc:
        queue.put(('ERROR', repr(exc)))
    finally:
        if engine is not None: engine.close()


class NativeConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.src, self.dst, self.db = root/'source', root/'target', root/'state.sqlite'
        self.src.mkdir(); self.dst.mkdir()
        self.engine = NativePosixMigration(self.src, self.dst, self.db)
        inv = IncrementalInventory(self.engine)
        first = inv.capture()['pass_id']
        (self.src/'object').write_bytes(b'payload' * 4096)
        second = inv.capture()['pass_id']
        self.planner = IncrementalPlanner(inv)
        self.plan = self.planner.create(first, second)['plan_id']

    def tearDown(self):
        self.engine.close(); self.temp.cleanup()

    def test_competing_processes_only_one_claim(self):
        ctx = mp.get_context('spawn')
        start, queue = ctx.Event(), ctx.Queue()
        workers = [ctx.Process(target=attempt_claim,args=(str(self.src),str(self.dst),str(self.db),self.plan,'object',start,queue)) for _ in range(3)]
        for worker in workers:worker.start()
        start.set()
        for worker in workers:
            worker.join(20)
            if worker.is_alive():worker.terminate();worker.join(5)
            self.assertEqual(worker.exitcode,0)
        results = [queue.get(timeout=5) for _ in workers]
        self.assertEqual(sum(r[0]=='CLAIMED' for r in results),1,results)
        self.assertEqual(sum(r[0]=='BLOCKED' for r in results),2,results)
        self.assertFalse((self.dst/'object').exists())

    def test_claim_survives_restart_and_rejects_reclaim(self):
        token = self.planner.claim_copy(self.plan,'object')['claim_token']
        self.engine.close()
        self.engine = NativePosixMigration(self.src,self.dst,self.db)
        inv = IncrementalInventory(self.engine)
        self.planner = IncrementalPlanner(inv)
        with self.assertRaises(MigrationBlocked):self.planner.claim_copy(self.plan,'object')
        executor = IncrementalExecutor(self.planner)
        result = executor.execute_claimed(self.plan,'object',claim_token=token)
        self.assertEqual(result['status'],'VERIFIED_POSIX_SUBSET')
        with self.assertRaises(MigrationBlocked):executor.execute_claimed(self.plan,'object',claim_token=token)

    def test_failed_claim_does_not_change_committed_status(self):
        token = self.planner.claim_copy(self.plan,'object')['claim_token']
        executor = IncrementalExecutor(self.planner)
        executor.execute_claimed(self.plan,'object',claim_token=token)
        with self.assertRaises(MigrationBlocked):self.planner.claim_copy(self.plan,'object')
        row=self.engine.db.execute('SELECT status,claim_token FROM incremental_tasks WHERE plan_id=? AND path=?',(self.plan,'object')).fetchone()
        self.assertEqual(row,('VERIFIED_POSIX_SUBSET',token))

if __name__ == '__main__':unittest.main()
