import tempfile,unittest
from pathlib import Path
from atomic_directory_quarantine import AtomicDirectoryQuarantineLedger
from directory_sync_health import assess_directory_sync_health,verify_directory_sync_health,SyncHealthError

D='a'*64
class DirectoryHealthTests(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
  self.ledger=AtomicDirectoryQuarantineLedger(str(Path(t.name)/'db.sqlite'),issuer_secret=b'a'*32)
  self.addCleanup(self.ledger.db.close)
 def baseline(self):
  self.ledger.db.execute("INSERT INTO directory_sync_state VALUES ('LDAP_EXPORT','v1',?)",(D,))
 def check(self,obs=None,**kw):
  return assess_directory_sync_health(self.ledger,now=kw.get('now',100),max_age_seconds=kw.get('ttl',30),observations=obs if obs is not None else [{'at':90,'status':'SUCCESS','digest':D}])
 def test_healthy_is_not_authorized(self):
  self.baseline();b=self.check();self.assertEqual(b['report']['status'],'OFFLINE_HEALTHY_NOT_AUTHORIZED');self.assertFalse(b['report']['cutover_authorized'])
 def test_no_baseline(self):self.assertEqual(self.check()['report']['status'],'BLOCKED_NO_DIRECTORY_BASELINE')
 def test_stale(self):
  self.baseline();self.assertEqual(self.check(now=200)['report']['status'],'BLOCKED_STALE_DIRECTORY')
 def test_mismatch(self):
  self.baseline();self.assertEqual(self.check([{'at':90,'status':'SUCCESS','digest':'b'*64}])['report']['status'],'BLOCKED_BASELINE_MISMATCH')
 def test_network_outage(self):
  self.baseline();self.assertEqual(self.check([{'at':80,'status':'SUCCESS','digest':D},{'at':90,'status':'NETWORK_FAILURE','digest':None}])['report']['status'],'BLOCKED_LAST_ATTEMPT_FAILED')
 def test_recovery(self):
  self.baseline();o=[{'at':70,'status':'NETWORK_FAILURE','digest':None},{'at':90,'status':'SUCCESS','digest':D}];self.assertEqual(self.check(o)['report']['status'],'OFFLINE_HEALTHY_NOT_AUTHORIZED')
 def test_no_success(self):
  self.baseline();self.assertEqual(self.check([{'at':90,'status':'TLS_FAILURE','digest':None}])['report']['status'],'BLOCKED_NO_SUCCESSFUL_SYNC')
 def test_bad_time(self):
  with self.assertRaises(SyncHealthError):self.check(now=-1)
 def test_out_of_order(self):
  with self.assertRaises(SyncHealthError):self.check([{'at':90,'status':'SUCCESS','digest':D},{'at':80,'status':'SUCCESS','digest':D}])
 def test_future_event(self):
  with self.assertRaises(SyncHealthError):self.check([{'at':101,'status':'SUCCESS','digest':D}])
 def test_failure_cannot_claim_digest(self):
  with self.assertRaises(SyncHealthError):self.check([{'at':90,'status':'IMPORT_FAILURE','digest':D}])
 def test_tamper(self):
  self.baseline();b=self.check();b['report']['status']='OFFLINE_HEALTHY_NOT_AUTHORIZED_FAKE';
  with self.assertRaises(SyncHealthError):verify_directory_sync_health(b,self.ledger,now=100,max_age_seconds=30,observations=[{'at':90,'status':'SUCCESS','digest':D}])
 def test_deterministic(self):
  self.baseline();self.assertEqual(self.check(),self.check())
 def test_read_only(self):
  self.baseline();before=self.ledger.db.total_changes;self.check();self.assertEqual(before,self.ledger.db.total_changes)
if __name__=='__main__':unittest.main()
