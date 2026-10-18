import tempfile,unittest
from pathlib import Path
from atomic_directory_quarantine import AtomicDirectoryQuarantineLedger
from directory_sync_journal import DirectorySyncJournal
from ldaps_atomic_journal_pipeline import sync_atomically
from test_ldaps_journaled_pipeline import collector, fail

class AtomicTests(unittest.TestCase):
 def setUp(self):
    t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
    self.path=str(Path(t.name)/'a.db')
    self.ledger=AtomicDirectoryQuarantineLedger(self.path,issuer_secret=b'x'*32)
    self.addCleanup(self.ledger.db.close)
    self.kw=dict(endpoint='ldaps://directory.example',base_dn='dc=example',version='v1',bind_dn='cn=svc',password='secret',ca_file='ca.pem')
 def run_sync(self,**kw):return sync_atomically(self.ledger,**(dict(event_id='e1',now=10,collector=collector)|self.kw|kw))
 def test_success(self):
    r=self.run_sync();self.assertFalse(r['cutover_authorized']);self.assertEqual(DirectorySyncJournal(self.ledger.db).verify()['count'],1)
 def test_collection_failure(self):
    with self.assertRaises(TimeoutError):self.run_sync(collector=fail)
    self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM directory_sync_state').fetchone()[0],0)
 def test_journal_failure_rolls_back_directory(self):
    DirectorySyncJournal(self.ledger.db)
    self.ledger.db.execute("CREATE TRIGGER deny_event BEFORE INSERT ON directory_sync_events BEGIN SELECT RAISE(ABORT,'deny'); END")
    with self.assertRaises(Exception):self.run_sync()
    self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM directory_sync_state').fetchone()[0],0)
    self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM reviewer_directory').fetchone()[0],0)
 def test_directory_failure_rolls_back_journal(self):
    self.ledger.db.execute("CREATE TRIGGER deny_directory BEFORE INSERT ON directory_sync_state BEGIN SELECT RAISE(ABORT,'deny'); END")
    with self.assertRaises(Exception):self.run_sync()
    self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM directory_sync_events').fetchone()[0],0)
 def test_duplicate(self):
    self.run_sync()
    with self.assertRaisesRegex(Exception,'DUPLICATE_EVENT_ID'):self.run_sync()
 def test_nonmonotonic(self):
    self.run_sync()
    with self.assertRaisesRegex(Exception,'NON_MONOTONIC_TIME'):self.run_sync(event_id='e2',now=9)
 def test_tamper(self):
    self.run_sync();self.ledger.db.execute("UPDATE directory_sync_events SET status='TLS_FAILURE'")
    with self.assertRaises(Exception):self.run_sync(event_id='e2',now=11)
 def test_reopen(self):
    self.run_sync();self.ledger.db.close()
    # reopen and verify durable journal
    import sqlite3
    db=sqlite3.connect(self.path)
    self.assertEqual(DirectorySyncJournal(db).verify()['count'],1)
    db.close()
 def test_bad_id(self):
    with self.assertRaisesRegex(Exception,'INVALID_EVENT_ID'):self.run_sync(event_id='bad id')
 def test_bad_time(self):
    with self.assertRaisesRegex(Exception,'INVALID_TIME'):self.run_sync(now=-1)
if __name__=='__main__':unittest.main()
