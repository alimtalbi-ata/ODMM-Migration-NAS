import tempfile, unittest
from pathlib import Path
from dual_review_ledger import DualReviewLedger, ApprovalError
from human_approval_registry import digest

class DualReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'ledger.db'
        self.db=DualReviewLedger(self.path)
        self.report={'migration_id':'mig1','status':'PENDING_HUMAN_AND_LIVE_VERIFICATION','cutover_authorized':False}
        self.bundle={'report':self.report,'sha256':digest(self.report)}
    def tearDown(self): self.db.close();self.tmp.cleanup()
    def record(self,role='security',reviewer='alice',ttl=30):
        return self.db.record('mig1',self.bundle,role,reviewer,ttl,now=100)
    def test_pending(self):
        self.record();self.assertEqual(self.db.assess('mig1',self.bundle,now=101)['status'],'PENDING_SECOND_REVIEW')
    def test_complete_never_authorizes(self):
        self.record();self.record('operations','bob');r=self.db.assess('mig1',self.bundle,now=101)
        self.assertEqual(r['status'],'DUAL_REVIEW_RECORDED_LIVE_VERIFICATION_REQUIRED');self.assertFalse(r['cutover_authorized'])
    def test_same_person_denied(self):
        self.record()
        with self.assertRaisesRegex(ApprovalError,'SEPARATION'): self.record('operations','alice')
    def test_duplicate_role_denied(self):
        self.record()
        with self.assertRaises(Exception): self.record('security','bob')
    def test_revocation(self):
        self.record();self.record('operations','bob');self.db.revoke('mig1','security',now=102)
        self.assertEqual(self.db.assess('mig1',self.bundle,now=103)['status'],'REVOKED')
    def test_expiration(self):
        self.record();self.record('operations','bob');self.assertEqual(self.db.assess('mig1',self.bundle,now=131)['status'],'EXPIRED')
    def test_tamper(self):
        self.record();self.record('operations','bob');bad={'report':dict(self.report,other=1),'sha256':self.bundle['sha256']}
        self.assertEqual(self.db.assess('mig1',bad,now=101)['status'],'INVALID_EVIDENCE')
    def test_changed_valid_evidence(self):
        self.record();changed=dict(self.report,revision=2);new={'report':changed,'sha256':digest(changed)}
        self.assertEqual(self.db.assess('mig1',new,now=101)['status'],'STALE_EVIDENCE')
    def test_restart(self):
        self.record();self.db.close();self.db=DualReviewLedger(self.path)
        self.assertEqual(self.db.assess('mig1',self.bundle,now=101)['status'],'PENDING_SECOND_REVIEW')
    def test_invalid_role(self):
        with self.assertRaises(ApprovalError): self.record('admin','alice')
    def test_invalid_ttl(self):
        with self.assertRaises(ApprovalError): self.record(ttl=0)
    def test_concurrent_connection(self):
        self.record()
        with DualReviewLedger(self.path) as other:
            with self.assertRaises(Exception): other.record('mig1',self.bundle,'security','bob',30,now=100)
