# V228.30: transaction rollback, tampering and stale claim safety.
import tempfile, unittest, sqlite3
from pathlib import Path
from native_posix_migration import NativePosixMigration, MigrationBlocked
from native_incremental_inventory import IncrementalInventory
from native_incremental_planner import IncrementalPlanner
from native_incremental_executor import IncrementalExecutor

class TransactionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); root=Path(self.tmp.name)
        self.source=root/'src'; self.target=root/'dst'; self.source.mkdir(); self.target.mkdir()
        self.database=root/'state.sqlite'; self.engine=NativePosixMigration(self.source,self.target,self.database)
        inv=IncrementalInventory(self.engine); first=inv.capture()['pass_id']
        (self.source/'file').write_bytes(b'payload'*128)
        second=inv.capture()['pass_id']; self.planner=IncrementalPlanner(inv)
        self.plan=self.planner.create(first,second)['plan_id']
    def tearDown(self): self.engine.close();self.tmp.cleanup()
    def row(self):
        return self.engine.db.execute('SELECT status,claim_token FROM incremental_tasks WHERE plan_id=? AND path=?',(self.plan,'file')).fetchone()
    def test_trigger_abort_claim_rolls_back(self):
        self.engine.db.execute('''CREATE TRIGGER block_claim BEFORE UPDATE OF status ON incremental_tasks
        WHEN NEW.status='CLAIMED' BEGIN SELECT RAISE(ABORT,'injected claim failure'); END''')
        with self.assertRaises(sqlite3.DatabaseError): self.planner.claim_copy(self.plan,'file')
        self.assertEqual(self.row(),('PENDING',None))
        self.assertFalse(self.engine.db.in_transaction)
        self.engine.db.execute('DROP TRIGGER block_claim')
        self.assertEqual(self.planner.claim_copy(self.plan,'file')['status'],'CLAIMED_NOT_EXECUTED')
    def test_stale_token_does_not_mutate_claim(self):
        token=self.planner.claim_copy(self.plan,'file')['claim_token']
        with self.assertRaises(MigrationBlocked): IncrementalExecutor(self.planner).execute_claimed(self.plan,'file',claim_token='stale')
        self.assertEqual(self.row(),('CLAIMED',token));self.assertFalse((self.target/'file').exists())
    def test_abort_final_ack_preserves_claim_for_review(self):
        token=self.planner.claim_copy(self.plan,'file')['claim_token']
        self.engine.db.execute('''CREATE TRIGGER block_verified BEFORE UPDATE OF status ON incremental_tasks
        WHEN NEW.status='VERIFIED_POSIX_SUBSET' BEGIN SELECT RAISE(ABORT,'injected commit failure'); END''')
        with self.assertRaises(sqlite3.DatabaseError): IncrementalExecutor(self.planner).execute_claimed(self.plan,'file',claim_token=token)
        self.assertEqual(self.row(),('CLAIMED',token))
        self.assertFalse(self.engine.db.in_transaction)
        self.engine.db.execute('DROP TRIGGER block_verified')
        with self.assertRaises(MigrationBlocked): IncrementalExecutor(self.planner).execute_claimed(self.plan,'file',claim_token=token)
        self.assertEqual(self.row(),('CLAIMED',token))
    def test_modified_claim_fails_closed(self):
        token=self.planner.claim_copy(self.plan,'file')['claim_token']
        self.engine.db.execute('UPDATE incremental_tasks SET claim_token=? WHERE plan_id=? AND path=?',('replacement',self.plan,'file'))
        with self.assertRaises(MigrationBlocked): IncrementalExecutor(self.planner).execute_claimed(self.plan,'file',claim_token=token)
        self.assertEqual(self.row(),('CLAIMED','replacement'))

if __name__=='__main__':unittest.main()
