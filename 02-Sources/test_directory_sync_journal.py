import sqlite3
import tempfile
import unittest
from pathlib import Path
from directory_sync_journal import DirectorySyncJournal,SyncJournalError
from directory_sync_health import SyncHealthError
from atomic_directory_quarantine import AtomicDirectoryQuarantineLedger
D='a'*64
class JournalTests(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
  self.path=str(Path(t.name)/'db.sqlite')
  self.ledger=AtomicDirectoryQuarantineLedger(self.path,issuer_secret=b'x'*32)
  self.addCleanup(self.ledger.db.close)
  self.j=DirectorySyncJournal(self.ledger.db)
 def test_append_verify(self):
  self.j.append('a',1,'NETWORK_FAILURE');self.j.append('b',2,'SUCCESS',D)
  self.assertEqual(self.j.verify()['count'],2)
 def test_duplicate(self):
  self.j.append('a',1,'SUCCESS',D)
  with self.assertRaises(SyncJournalError):self.j.append('a',2,'SUCCESS',D)
 def test_time(self):
  self.j.append('a',10,'SUCCESS',D)
  with self.assertRaises(SyncJournalError):self.j.append('b',9,'SUCCESS',D)
 def test_bad_digest(self):
  with self.assertRaises(SyncJournalError):self.j.append('a',1,'SUCCESS','wrong')
 def test_failure_digest(self):
  with self.assertRaises(SyncJournalError):self.j.append('a',1,'TLS_FAILURE',D)
 def test_invalid_id(self):
  with self.assertRaises(SyncJournalError):self.j.append('x y',1,'SUCCESS',D)
 def test_tamper(self):
  self.j.append('a',1,'SUCCESS',D)
  self.ledger.db.execute("UPDATE directory_sync_events SET status='TLS_FAILURE'")
  with self.assertRaises(SyncJournalError):self.j.verify()
 def test_refuse_append_after_tamper(self):
  self.j.append('a',1,'SUCCESS',D)
  self.ledger.db.execute("UPDATE directory_sync_events SET digest=?",('b'*64,))
  with self.assertRaises(SyncJournalError):self.j.append('b',2,'SUCCESS',D)
  self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM directory_sync_events').fetchone()[0],1)
 def test_reopen(self):
  self.j.append('a',1,'SUCCESS',D)
  c=sqlite3.connect(self.path)
  try:self.assertEqual(DirectorySyncJournal(c).verify()['count'],1)
  finally:c.close()
 def test_health(self):
  self.ledger.db.execute("INSERT INTO directory_sync_state VALUES ('LDAP_EXPORT','v1',?)",(D,))
  self.j.append('a',90,'SUCCESS',D)
  r=self.j.assess_health(self.ledger,now=100,max_age_seconds=30)
  self.assertEqual(r['report']['status'],'OFFLINE_HEALTHY_NOT_AUTHORIZED')
  self.assertFalse(r['report']['cutover_authorized'])
 def test_health_failure(self):
  self.ledger.db.execute("INSERT INTO directory_sync_state VALUES ('LDAP_EXPORT','v1',?)",(D,))
  self.j.append('a',80,'SUCCESS',D);self.j.append('b',90,'NETWORK_FAILURE')
  self.assertEqual(self.j.assess_health(self.ledger,now=100,max_age_seconds=30)['report']['status'],'BLOCKED_LAST_ATTEMPT_FAILED')
 def test_empty(self):
  with self.assertRaises(SyncJournalError):self.j.observations()
 def test_rollback(self):
  self.j.append('a',1,'SUCCESS',D)
  with self.assertRaises(SyncJournalError):self.j.append('b',1,'SUCCESS',D)
  self.assertEqual(self.j.verify()['count'],1)
if __name__=='__main__':unittest.main()
