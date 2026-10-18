import tempfile
import unittest
from pathlib import Path
from authenticated_review_ledger import AuthenticatedReviewLedger, sign_assertion
from human_approval_registry import digest, ApprovalError

KEY=b'a'*32
class TestAuthenticatedReviewLedger(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'a.db'
        report={'migration_id':'M1','status':'PENDING_HUMAN_AND_LIVE_VERIFICATION','cutover_authorized':False}
        self.bundle={'report':report,'sha256':digest(report)}
    def tearDown(self): self.tmp.cleanup()
    def assertion(self,**kwargs):
        d=dict(migration_id='M1',evidence_hash=self.bundle['sha256'],role='security',reviewer='alice',nonce='n1',issued_at=10,expires_at=50)
        d.update(kwargs); return sign_assertion(KEY,**d)
    def test_success(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l:
            self.assertFalse(l.record_attested('M1',self.bundle,self.assertion(),now=11)['cutover_authorized'])
            self.assertEqual(l.verify_journal()['events'],1)
    def test_dual_roles(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l:
            l.record_attested('M1',self.bundle,self.assertion(),now=11)
            l.record_attested('M1',self.bundle,self.assertion(role='operations',reviewer='bob',nonce='n2'),now=12)
            self.assertFalse(l.assess('M1',self.bundle,now=13)['cutover_authorized'])
    def test_replay(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l:
            l.record_attested('M1',self.bundle,self.assertion(),now=11)
            with self.assertRaises(Exception): l.record_attested('M1',self.bundle,self.assertion(role='operations',reviewer='bob',nonce='n1'),now=12)
            self.assertEqual(l.verify_journal()['events'],1)
    def test_bad_signature(self):
        a=self.assertion(); a['reviewer']='mallory'
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l:
            with self.assertRaises(ApprovalError): l.record_attested('M1',self.bundle,a,now=11)
    def test_expired(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l:
            with self.assertRaises(ApprovalError): l.record_attested('M1',self.bundle,self.assertion(),now=50)
    def test_future(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l:
            with self.assertRaises(ApprovalError): l.record_attested('M1',self.bundle,self.assertion(),now=9)
    def test_changed_evidence(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l:
            with self.assertRaises(ApprovalError): l.record_attested('M1',self.bundle,self.assertion(evidence_hash='0'*64),now=11)
    def test_wrong_key(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=b'b'*32) as l:
            with self.assertRaises(ApprovalError): l.record_attested('M1',self.bundle,self.assertion(),now=11)
    def test_short_key(self):
        with self.assertRaises(ApprovalError): AuthenticatedReviewLedger(self.path,issuer_secret=b'a')
    def test_invalid_role(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l:
            with self.assertRaises(ApprovalError): l.record_attested('M1',self.bundle,self.assertion(role='admin'),now=11)
    def test_journal_failure_atomic(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l:
            l.db.execute("CREATE TRIGGER reject_event BEFORE INSERT ON review_events BEGIN SELECT RAISE(ABORT,'failure'); END")
            with self.assertRaises(Exception): l.record_attested('M1',self.bundle,self.assertion(),now=11)
            self.assertEqual(l.db.execute('SELECT COUNT(*) FROM consumed_review_nonces').fetchone()[0],0)
            self.assertEqual(l.db.execute('SELECT COUNT(*) FROM dual_reviews').fetchone()[0],0)
    def test_persistence(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l: l.record_attested('M1',self.bundle,self.assertion(),now=11)
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l: self.assertEqual(l.verify_journal()['events'],1)
    def test_tampered_journal_blocks(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l:
            l.record_attested('M1',self.bundle,self.assertion(),now=11)
            l.db.execute("UPDATE review_events SET event_json='{}'")
            with self.assertRaises(ApprovalError): l.record_attested('M1',self.bundle,self.assertion(role='operations',reviewer='bob',nonce='n2'),now=12)
    def test_same_reviewer(self):
        with AuthenticatedReviewLedger(self.path,issuer_secret=KEY) as l:
            l.record_attested('M1',self.bundle,self.assertion(),now=11)
            with self.assertRaises(ApprovalError): l.record_attested('M1',self.bundle,self.assertion(role='operations',nonce='n2'),now=12)
