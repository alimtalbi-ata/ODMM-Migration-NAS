import json
import unittest
import sqlite3
from pathlib import Path
from ldaps_ipc_review_anchor import AnchoredIPCReview
from ldaps_ipc_persistent_identity import IdentityPinError
from test_ldaps_ipc_durable_review import DurableReviewTests

class ReviewAnchorTests(unittest.TestCase):
    interrupt = DurableReviewTests.interrupt
    archive = DurableReviewTests.archive
    def setUp(self):
        DurableReviewTests.setUp(self)
        self.anchor = AnchoredIPCReview(self.store,anchor_path=self.path.parent/'review-anchor.json',key=b'a'*32)
    def test_enroll_verify(self):
        self.anchor.enroll(operator_confirmed=True)
        self.assertEqual(self.anchor.verify()['count'],0)
    def test_confirmation_required(self):
        with self.assertRaises(IdentityPinError):self.anchor.enroll(operator_confirmed=False)
    def test_missing(self):
        with self.assertRaisesRegex(IdentityPinError,'MISSING'):self.anchor.verify()
    def test_wrong_key(self):
        self.anchor.enroll(operator_confirmed=True)
        other=AnchoredIPCReview(self.store,anchor_path=self.anchor.path,key=b'z'*32)
        with self.assertRaisesRegex(IdentityPinError,'INVALID'):other.verify()
    def test_ledger_advance_detected(self):
        self.anchor.enroll(operator_confirmed=True)
        self.archive()
        with self.assertRaisesRegex(IdentityPinError,'MISMATCH'):self.anchor.verify()
    def test_explicit_checkpoint(self):
        self.anchor.enroll(operator_confirmed=True)
        self.archive()
        state=self.store.verify()
        self.anchor.checkpoint(operator_confirmed=True,expected_count=state['count'],expected_last_mac=state['last_mac'])
        self.assertEqual(self.anchor.verify()['count'],1)
    def test_stale_checkpoint_rejected(self):
        self.anchor.enroll(operator_confirmed=True)
        self.archive()
        with self.assertRaisesRegex(IdentityPinError,'STALE'):self.anchor.checkpoint(operator_confirmed=True,expected_count=0,expected_last_mac='0'*64)
    def test_rollback_detected(self):
        self.anchor.enroll(operator_confirmed=True)
        self.archive()
        state=self.store.verify()
        self.anchor.checkpoint(operator_confirmed=True,expected_count=state['count'],expected_last_mac=state['last_mac'])
        with sqlite3.connect(self.path) as db:db.execute('DELETE FROM ipc_review_receipts')
        with self.assertRaisesRegex(IdentityPinError,'MISMATCH'):self.anchor.verify()
        with self.assertRaisesRegex(IdentityPinError,'ROLLBACK'):self.anchor.checkpoint(operator_confirmed=True,expected_count=0,expected_last_mac='0'*64)
    def test_tamper_anchor(self):
        self.anchor.enroll(operator_confirmed=True)
        data=json.loads(self.anchor.path.read_text());data['state']['count']=8
        self.anchor.path.write_text(json.dumps(data))
        with self.assertRaisesRegex(IdentityPinError,'INVALID'):self.anchor.verify()
    def test_symlink_rejected(self):
        link=self.path.parent/'link'
        link.symlink_to(self.path)
        with self.assertRaises(IdentityPinError):AnchoredIPCReview(self.store,anchor_path=link,key=b'a'*32)
    def test_no_automatic_checkpoint(self):
        self.anchor.enroll(operator_confirmed=True)
        self.anchor.archive(security_token='alice',operations_token='bob',now=100,
          expected_evidence_sha256=self.recon.report()['evidence_sha256'],operator_confirmed=True)
        with self.assertRaisesRegex(IdentityPinError,'MISMATCH'):self.anchor.verify()
    def test_restart(self):
        self.anchor.enroll(operator_confirmed=True)
        reopened=AnchoredIPCReview(self.store,anchor_path=self.anchor.path,key=b'a'*32)
        self.assertEqual(reopened.verify()['count'],0)
