import tempfile, unittest, sqlite3
from pathlib import Path
from atomic_review_ledger import AtomicReviewLedger
from human_approval_registry import digest, ApprovalError

class TestAtomicReviewLedger(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'ledger.db'
        report={'migration_id':'M1','status':'PENDING_HUMAN_AND_LIVE_VERIFICATION','cutover_authorized':False}
        self.bundle={'report':report,'sha256':digest(report)}
    def tearDown(self): self.tmp.cleanup()
    def test_atomic_record_and_chain(self):
        with AtomicReviewLedger(self.path) as l:
            l.record('M1',self.bundle,'security','alice',100,now=10)
            l.record('M1',self.bundle,'operations','bob',100,now=11)
            self.assertEqual(l.verify_journal()['events'],2)
            self.assertFalse(l.assess('M1',self.bundle,now=12)['cutover_authorized'])
    def test_revoke_is_journaled(self):
        with AtomicReviewLedger(self.path) as l:
            l.record('M1',self.bundle,'security','alice',100,now=10)
            l.revoke('M1','security',now=11)
            self.assertEqual(l.verify_journal()['events'],2)
            self.assertEqual(l.assess('M1',self.bundle,now=12)['status'],'REVOKED')
    def test_duplicate_rolls_back_without_event(self):
        with AtomicReviewLedger(self.path) as l:
            l.record('M1',self.bundle,'security','alice',100,now=10)
            with self.assertRaises(sqlite3.IntegrityError): l.record('M1',self.bundle,'security','charlie',100,now=11)
            self.assertEqual(l.verify_journal()['events'],1)
    def test_journal_failure_rolls_back_review(self):
        with AtomicReviewLedger(self.path) as l:
            l.db.execute('CREATE TRIGGER reject_event BEFORE INSERT ON review_events BEGIN SELECT RAISE(ABORT,\'journal unavailable\'); END')
            with self.assertRaises(sqlite3.IntegrityError): l.record('M1',self.bundle,'security','alice',100,now=10)
            self.assertEqual(l.db.execute('SELECT COUNT(*) FROM dual_reviews').fetchone()[0],0)
    def test_revocation_failure_rolls_back(self):
        with AtomicReviewLedger(self.path) as l:
            l.record('M1',self.bundle,'security','alice',100,now=10)
            l.db.execute("CREATE TRIGGER reject_event BEFORE INSERT ON review_events BEGIN SELECT RAISE(ABORT,'journal unavailable'); END")
            with self.assertRaises(sqlite3.IntegrityError): l.revoke('M1','security',now=11)
            self.assertIsNone(l.db.execute('SELECT revoked_at FROM dual_reviews').fetchone()[0])
    def test_persistence(self):
        with AtomicReviewLedger(self.path) as l: l.record('M1',self.bundle,'security','alice',100,now=10)
        with AtomicReviewLedger(self.path) as l: self.assertEqual(l.verify_journal()['events'],1)
    def test_tamper_detection(self):
        with AtomicReviewLedger(self.path) as l:
            l.record('M1',self.bundle,'security','alice',100,now=10)
            l.db.execute("UPDATE review_events SET event_json='{}'")
            self.assertEqual(l.verify_journal()['status'],'TAMPER_DETECTED')
    def test_same_reviewer_blocked(self):
        with AtomicReviewLedger(self.path) as l:
            l.record('M1',self.bundle,'security','alice',100,now=10)
            with self.assertRaises(ApprovalError): l.record('M1',self.bundle,'operations','alice',100,now=11)
            self.assertEqual(l.verify_journal()['events'],1)
if __name__=='__main__': unittest.main()
