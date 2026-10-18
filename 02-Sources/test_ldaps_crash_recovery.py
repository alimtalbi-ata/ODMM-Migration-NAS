import sqlite3
import tempfile
import unittest
from pathlib import Path
from atomic_directory_quarantine import AtomicDirectoryQuarantineLedger
from ldaps_crash_recovery import CrashRecoveryCoordinator,CrashRecoveryError
from directory_sync_journal import DirectorySyncJournal,SyncJournalError
from test_ldaps_journaled_pipeline import collector,fail

class RecoveryTests(unittest.TestCase):
 def setUp(self):
    t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
    self.path=str(Path(t.name)/'r.db')
    self.ledger=AtomicDirectoryQuarantineLedger(self.path,issuer_secret=b'x'*32)
    self.addCleanup(lambda: self.ledger.db.close() if self.ledger.db else None)
    self.c=CrashRecoveryCoordinator(self.ledger)
    self.kw=dict(endpoint='ldaps://directory.example',base_dn='dc=example',version='v1',bind_dn='cn=svc',password='secret',ca_file='ca.pem',collector=collector)
 def test_success(self):
    r=self.c.run(event_id='a',now=10,**self.kw)
    self.assertEqual(r['attempt_state'],'COMMITTED');self.assertFalse(r['cutover_authorized'])
 def test_crash_before_collection(self):
    self.c.begin('a',10)
    self.assertEqual(self.c.reconcile()[0]['state'],'INTERRUPTED')
 def test_crash_after_commit_before_mark(self):
    from ldaps_atomic_journal_pipeline import sync_atomically
    self.c.begin('a',10)
    sync_atomically(self.ledger,event_id='a',now=10,**self.kw)
    self.assertEqual(self.c.reconcile()[0]['state'],'COMMITTED')
 def test_crash_with_failure_event(self):
    self.c.begin('a',10)
    DirectorySyncJournal(self.ledger.db).append('a',10,'NETWORK_FAILURE')
    self.assertEqual(self.c.reconcile()[0]['state'],'FAILED')
 def test_failed_collection(self):
    with self.assertRaises(TimeoutError):self.c.run(event_id='a',now=10,**(self.kw|{'collector':fail}))
    self.assertEqual(self.c.inspect('a')['state'],'FAILED')
 def test_duplicate_intent(self):
    self.c.begin('a',10)
    with self.assertRaisesRegex(CrashRecoveryError,'DUPLICATE_INTENT'):self.c.begin('a',10)
 def test_no_replay(self):
    self.c.begin('a',10);self.c.reconcile()
    with self.assertRaises(CrashRecoveryError):self.c.begin('a',10)
 def test_reopen(self):
    self.c.begin('a',10)
    self.ledger.db.close();self.ledger.db=sqlite3.connect(self.path)
    self.c=CrashRecoveryCoordinator(self.ledger)
    self.assertEqual(self.c.reconcile()[0]['state'],'INTERRUPTED')
 def test_tampered_journal_blocks_reconcile(self):
    DirectorySyncJournal(self.ledger.db).append('x',1,'NETWORK_FAILURE')
    self.c.begin('a',10)
    self.ledger.db.execute("UPDATE directory_sync_events SET status='TLS_FAILURE'")
    with self.assertRaises(SyncJournalError):self.c.reconcile()
    self.assertEqual(self.c.inspect('a')['state'],'STARTED')
 def test_invalid_inputs(self):
    for e,n in [('bad id',10),('ok',-1),('ok',True)]:
        with self.assertRaises(CrashRecoveryError):self.c.begin(e,n)
 def test_idempotent_reconciliation(self):
    self.c.begin('a',10);self.c.reconcile();self.assertEqual(self.c.reconcile(),[])
 def test_no_directory_mutation_on_interrupted(self):
    self.c.begin('a',10);self.c.reconcile()
    self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM directory_sync_state').fetchone()[0],0)
if __name__=='__main__':unittest.main()
