import tempfile
import unittest
from pathlib import Path
from atomic_directory_quarantine import AtomicDirectoryQuarantineLedger
from human_approval_registry import ApprovalError, digest

M='migration-test'
def readiness():
    r={'migration_id':M,'status':'PENDING_HUMAN_AND_LIVE_VERIFICATION','cutover_authorized':False}
    return {'report':r,'sha256':digest(r)}
def export(version='v1', alice=True, bob=True):
    return {'source':'AD_EXPORT','version':version,'accounts':[
        {'id':'alice','enabled':alice,'groups':['ODMM_SECURITY_REVIEWERS']},
        {'id':'bob','enabled':bob,'groups':['ODMM_OPERATIONS_REVIEWERS']}]}

class AtomicDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'db.sqlite'
        self.ledger=AtomicDirectoryQuarantineLedger(self.path,issuer_secret=b'x'*32)
        self.ledger.record(M,readiness(),'security','alice',3600,now=10)
        self.ledger.record(M,readiness(),'operations','bob',3600,now=10)
    def tearDown(self):
        self.ledger.close(); self.tmp.cleanup()
    def apply(self, e, previous=None):
        return self.ledger.synchronize_and_quarantine(e,expected_previous_digest=previous,now=20)
    def test_first_sync_conservative_quarantine(self):
        result=self.apply(export())
        self.assertEqual(result['quarantined_migrations'],[M])
        self.assertFalse(result['cutover_authorized'])
        self.assertEqual(self.ledger.assess(M,readiness(),now=20)['status'],'QUARANTINED_REVIEW_REQUIRED')
    def test_no_change_without_approvals(self):
        self.ledger.db.execute('DELETE FROM dual_reviews')
        self.assertEqual(self.apply(export())['quarantined_migrations'],[])
    def test_compare_and_swap(self):
        first=self.apply(export())
        with self.assertRaises(ApprovalError): self.apply(export('v2'),previous='0'*64)
        self.assertEqual(self.ledger.db.execute('SELECT version FROM directory_sync_state').fetchone()[0],'v1')
    def test_reused_version_rejected(self):
        first=self.apply(export())
        with self.assertRaises(ApprovalError): self.apply(export('v1',False),first['sha256'])
    def test_audit_failure_rolls_back_all(self):
        self.ledger.db.execute("CREATE TRIGGER deny_event BEFORE INSERT ON review_events WHEN NEW.event_json LIKE '%REVIEWS_QUARANTINED%' BEGIN SELECT RAISE(ABORT,'audit failed'); END")
        with self.assertRaises(Exception): self.apply(export())
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM directory_sync_state').fetchone()[0],0)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM review_quarantines').fetchone()[0],0)
    def test_tamper_blocks_sync(self):
        self.ledger.db.execute("UPDATE review_events SET event_json='{}' WHERE seq=1")
        with self.assertRaises(ApprovalError): self.apply(export())
    def test_bad_timestamp(self):
        with self.assertRaises(ApprovalError): self.ledger.synchronize_and_quarantine(export(),now=True)
    def test_restart(self):
        self.apply(export()); self.ledger.close()
        self.ledger=AtomicDirectoryQuarantineLedger(self.path,issuer_secret=b'x'*32)
        self.assertEqual(self.ledger.assess(M,readiness(),now=21)['status'],'QUARANTINED_REVIEW_REQUIRED')
    def test_unchanged_snapshot_after_quarantine(self):
        first=self.apply(export())
        second=self.apply(export('v2'),first['sha256'])
        self.assertEqual(second['quarantined_migrations'],[])
    def test_invalid_export_rolls_back(self):
        with self.assertRaises(ApprovalError): self.apply({'source':'AD_EXPORT','version':'v1','accounts':[]})
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM directory_sync_state').fetchone()[0],0)

if __name__=='__main__': unittest.main()
