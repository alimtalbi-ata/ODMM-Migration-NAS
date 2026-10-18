import hashlib
import tempfile
import unittest
from pathlib import Path
from human_approval_registry import ApprovalError, digest
from review_quarantine import QuarantinedReviewLedger

MIG='migration-test'
def readiness():
    r={'migration_id':MIG,'status':'PENDING_HUMAN_AND_LIVE_VERIFICATION','cutover_authorized':False}
    return {'report':r,'sha256':digest(r)}
def freshness(now=100, reasons=None):
    r={'schema':'odmm.directory-freshness.v1','status':'REVIEW_REQUIRED',
       'reasons':reasons if reasons is not None else ['REVIEWER_MEMBERSHIP_DRIFT'],
       'now':now,'cutover_authorized':False,'directory_authenticated':False}
    return {'report':r,'sha256':digest(r)}

class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'review.db'
        self.ledger=QuarantinedReviewLedger(self.path,issuer_secret=b'x'*32)
        self.ledger.record(MIG,readiness(),'security','alice',3600,now=90)
        self.ledger.record(MIG,readiness(),'operations','bob',3600,now=90)
    def tearDown(self):
        self.ledger.close(); self.tmp.cleanup()
    def test_quarantine_revokes_both(self):
        self.assertEqual(self.ledger.quarantine(MIG,readiness(),freshness(),now=100)['status'],'QUARANTINED_REVIEW_REQUIRED')
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM dual_reviews WHERE revoked_at=100').fetchone()[0],2)
        self.assertEqual(self.ledger.assess(MIG,readiness(),now=100)['status'],'QUARANTINED_REVIEW_REQUIRED')
    def test_journal_valid(self):
        self.ledger.quarantine(MIG,readiness(),freshness(),now=100)
        self.assertEqual(self.ledger.verify_journal()['status'],'CHAIN_INTACT_UNAUTHENTICATED')
    def test_duplicate_rejected(self):
        self.ledger.quarantine(MIG,readiness(),freshness(),now=100)
        with self.assertRaises(ApprovalError): self.ledger.quarantine(MIG,readiness(),freshness(),now=100)
    def test_invalid_digest_rejected(self):
        b=freshness(); b['sha256']='0'*64
        with self.assertRaises(ApprovalError): self.ledger.quarantine(MIG,readiness(),b,now=100)
    def test_stale_timestamp_rejected(self):
        with self.assertRaises(ApprovalError): self.ledger.quarantine(MIG,readiness(),freshness(99),now=100)
    def test_no_drift_rejected(self):
        b=freshness(reasons=[])
        with self.assertRaises(ApprovalError): self.ledger.quarantine(MIG,readiness(),b,now=100)
    def test_tampered_journal_rejected(self):
        self.ledger.db.execute("UPDATE review_events SET event_json='{}' WHERE seq=1")
        with self.assertRaises(ApprovalError): self.ledger.quarantine(MIG,readiness(),freshness(),now=100)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM review_quarantines').fetchone()[0],0)
    def test_audit_insert_failure_rolls_back(self):
        self.ledger.db.execute("CREATE TRIGGER deny_quarantine BEFORE INSERT ON review_events WHEN NEW.event_json LIKE '%REVIEWS_QUARANTINED%' BEGIN SELECT RAISE(ABORT,'audit failed'); END")
        with self.assertRaises(Exception): self.ledger.quarantine(MIG,readiness(),freshness(),now=100)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM review_quarantines').fetchone()[0],0)
        self.assertEqual(self.ledger.db.execute('SELECT COUNT(*) FROM dual_reviews WHERE revoked_at IS NOT NULL').fetchone()[0],0)
    def test_restart_persistence(self):
        self.ledger.quarantine(MIG,readiness(),freshness(),now=100)
        self.ledger.close()
        self.ledger=QuarantinedReviewLedger(self.path,issuer_secret=b'x'*32)
        self.assertEqual(self.ledger.assess(MIG,readiness(),now=101)['status'],'QUARANTINED_REVIEW_REQUIRED')
    def test_invalid_time(self):
        with self.assertRaises(ApprovalError): self.ledger.quarantine(MIG,readiness(),freshness(),now=True)

if __name__=='__main__': unittest.main()
