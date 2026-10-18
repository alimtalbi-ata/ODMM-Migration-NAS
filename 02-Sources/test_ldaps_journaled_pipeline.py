import tempfile
import unittest
from pathlib import Path
from atomic_directory_quarantine import AtomicDirectoryQuarantineLedger
from ldaps_journaled_pipeline import sync_and_record, JournaledPipelineError
from directory_sync_journal import DirectorySyncJournal
from directory_snapshot_adapter import normalize_directory_export

EXPORT={'source':'LDAP_EXPORT','version':'v1','accounts':[{'id':'sec','enabled':True,'groups':['ODMM_SECURITY_REVIEWERS']}]}
def collector(**kwargs):
    b=normalize_directory_export(EXPORT)
    return {'transport':'LDAPS_TLS_CA_VALIDATED_BY_CLIENT','authenticated':False,'cutover_authorized':False,**b}
def fail(**kwargs):raise TimeoutError('network timeout')
def tls_fail(**kwargs):raise ValueError('TLS certificate invalid')
class PipelineTests(unittest.TestCase):
 def setUp(self):
    t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
    self.ledger=AtomicDirectoryQuarantineLedger(str(Path(t.name)/'test.db'),issuer_secret=b'x'*32)
    self.addCleanup(self.ledger.db.close)
    self.kw={'endpoint':'ldaps://directory.example','base_dn':'dc=example','version':'v1','bind_dn':'cn=svc','password':'secret','ca_file':'ca.pem'}
 def run_sync(self,event_id='evt1',now=10,collector=collector,**overrides):
    return sync_and_record(self.ledger,event_id=event_id,now=now,collector=collector,**(self.kw|overrides))
 def test_success(self):
    r=self.run_sync();j=DirectorySyncJournal(self.ledger.db)
    self.assertFalse(r['cutover_authorized']);self.assertEqual(j.observations()[0]['status'],'SUCCESS')
    self.assertEqual(j.observations()[0]['digest'],r['sha256'])
 def test_failure_logged(self):
    with self.assertRaises(TimeoutError):self.run_sync(collector=fail)
    self.assertEqual(DirectorySyncJournal(self.ledger.db).observations()[0]['status'],'NETWORK_FAILURE')
    self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM directory_sync_state').fetchone()[0],0)
 def test_tls_failure(self):
    with self.assertRaises(ValueError):self.run_sync(collector=tls_fail)
    self.assertEqual(DirectorySyncJournal(self.ledger.db).observations()[0]['status'],'TLS_FAILURE')
 def test_duplicate_before_collection(self):
    self.run_sync()
    with self.assertRaisesRegex(JournaledPipelineError,'DUPLICATE_EVENT_ID'):self.run_sync()
 def test_nonmonotonic(self):
    self.run_sync()
    with self.assertRaisesRegex(JournaledPipelineError,'NON_MONOTONIC_TIME'):self.run_sync('evt2',9)
 def test_recovery_success_after_failure(self):
    with self.assertRaises(TimeoutError):self.run_sync(collector=fail)
    r=self.run_sync('evt2',11)
    self.assertEqual([x['status'] for x in DirectorySyncJournal(self.ledger.db).observations()],['NETWORK_FAILURE','SUCCESS'])
    self.assertFalse(r['production_qualified'])
 def test_health(self):
    self.run_sync()
    r=DirectorySyncJournal(self.ledger.db).assess_health(self.ledger,now=11,max_age_seconds=60)
    self.assertEqual(r['report']['status'],'OFFLINE_HEALTHY_NOT_AUTHORIZED')
 def test_tampered_journal_refuses_import(self):
    self.run_sync()
    self.ledger.db.execute("UPDATE directory_sync_events SET status='TLS_FAILURE'")
    with self.assertRaises(Exception):self.run_sync('evt2',11)
 def test_bad_event_id(self):
    with self.assertRaisesRegex(JournaledPipelineError,'INVALID_EVENT_ID'):self.run_sync('bad id')
 def test_invalid_time(self):
    with self.assertRaisesRegex(JournaledPipelineError,'INVALID_TIME'):self.run_sync(now=-1)
 def test_bad_import_logged(self):
    with self.assertRaises(Exception):self.run_sync(collector=lambda **kw:{'bad':'snapshot'})
    self.assertEqual(DirectorySyncJournal(self.ledger.db).observations()[0]['status'],'IMPORT_FAILURE')
if __name__=='__main__':unittest.main()
