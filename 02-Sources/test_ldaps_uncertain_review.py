import sqlite3,unittest
from ldaps_crash_reconciliation import CrashReconciliationLedger
from ldaps_durable_target import DurableFencedTarget
from ldaps_uncertain_review import UncertainReviewLedger,UncertainReviewError
class C:
    def __init__(self,db):self.db=db
class Tests(unittest.TestCase):
    def setUp(self):
        self.a=sqlite3.connect(':memory:',isolation_level=None);self.b=sqlite3.connect(':memory:',isolation_level=None)
        self.target=DurableFencedTarget(self.b);self.target.advance_epoch('e',1)
        self.rec=CrashReconciliationLedger(C(self.a),self.target);self.review=UncertainReviewLedger(self.rec)
        self.obs=self.rec.record('e','r',observed_at=100)
    def tearDown(self):self.a.close();self.b.close()
    def decide(self,**kw):
        args=dict(observation_hash=self.obs['evidence_sha256'],reviewer='operator',action='INVESTIGATE',decided_at=101)
        args.update(kw);return self.review.decide('e','r',**args)
    def test_success(self):self.assertEqual(self.decide()['status'],'HUMAN_REVIEW_RECORDED')
    def test_no_execution(self):self.assertFalse(self.decide()['execution_authorized'])
    def test_no_cutover(self):self.assertFalse(self.decide()['cutover_authorized'])
    def test_no_retry(self):self.assertFalse(self.decide()['automatic_retry'])
    def test_duplicate(self):
        self.decide()
        with self.assertRaises(sqlite3.IntegrityError):self.decide()
    def test_wrong_hash(self):
        with self.assertRaises(UncertainReviewError):self.decide(observation_hash='0'*64)
    def test_expired(self):
        with self.assertRaises(UncertainReviewError):self.decide(decided_at=5000)
    def test_future_observation(self):
        with self.assertRaises(UncertainReviewError):self.decide(decided_at=99)
    def test_invalid_action(self):
        with self.assertRaises(UncertainReviewError):self.decide(action='RETRY')
    def test_invalid_reviewer(self):
        with self.assertRaises(UncertainReviewError):self.decide(reviewer=' ')
    def test_audit_tamper(self):
        self.decide();self.a.execute("UPDATE ldaps_uncertain_reviews SET action='BLOCK'")
        with self.assertRaises(UncertainReviewError):self.review.verify()
    def test_changed_evidence(self):
        self.target.apply(event_id='e',owner='w',epoch=1,operation='READ_ONLY',permit_hash='p',request_id='r')
        with self.assertRaises(UncertainReviewError):self.decide()
    def test_stale_after_new_observation(self):
        self.rec.record('e','r',observed_at=101)
        with self.assertRaises(UncertainReviewError):self.decide(decided_at=102)
    def test_rollback(self):
        self.a.execute("CREATE TRIGGER deny_review BEFORE INSERT ON ldaps_uncertain_reviews BEGIN SELECT RAISE(ABORT,'deny'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.decide()
        self.assertEqual(self.review.verify()['count'],0)
    def test_block(self):self.assertEqual(self.decide(action='BLOCK')['status'],'HUMAN_REVIEW_RECORDED')
if __name__=='__main__':unittest.main()
