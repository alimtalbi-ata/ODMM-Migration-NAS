import json
import unittest
from ldaps_ipc_external_witness import ExternalReviewWitness
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_ipc_review_anchor import AnchoredIPCReview
from test_ldaps_ipc_review_anchor import ReviewAnchorTests

class WitnessTests(unittest.TestCase):
    interrupt = ReviewAnchorTests.interrupt
    archive = ReviewAnchorTests.archive
    def setUp(self):
        ReviewAnchorTests.setUp(self)
        self.anchor.enroll(operator_confirmed=True)
        self.witness = ExternalReviewWitness(self.anchor, witness_path=self.path.parent/'separate-witness.json',key=b'w'*32)
    def advance(self):
        self.archive()
        state=self.store.verify()
        self.anchor.checkpoint(operator_confirmed=True,expected_count=state['count'],expected_last_mac=state['last_mac'])
        return state
    def test_enroll_verify(self):
        self.witness.enroll(operator_confirmed=True)
        self.assertEqual(self.witness.verify()['count'],0)
    def test_requires_confirmation(self):
        with self.assertRaises(IdentityPinError):self.witness.enroll(operator_confirmed=False)
    def test_missing(self):
        with self.assertRaisesRegex(IdentityPinError,'MISSING'):self.witness.verify()
    def test_publish_and_restart(self):
        self.witness.enroll(operator_confirmed=True)
        state=self.advance()
        self.witness.publish(operator_confirmed=True,expected_count=state['count'],expected_last_mac=state['last_mac'])
        reopened=ExternalReviewWitness(self.anchor,witness_path=self.witness.path,key=b'w'*32)
        self.assertEqual(reopened.verify()['count'],1)
    def test_detect_anchor_rollback(self):
        self.witness.enroll(operator_confirmed=True)
        original=self.anchor.path.read_bytes()
        state=self.advance()
        self.witness.publish(operator_confirmed=True,expected_count=state['count'],expected_last_mac=state['last_mac'])
        self.anchor.path.write_bytes(original)
        self.assertEqual(self.witness.restoration_report()['status'],'EVIDENCE_INVALID_MANUAL_REVIEW')
    def test_unpublished_advance(self):
        self.witness.enroll(operator_confirmed=True)
        self.advance()
        self.assertEqual(self.witness.restoration_report()['status'],'ROLLBACK_OR_DIVERGENCE_MANUAL_REVIEW')
    def test_stale_evidence(self):
        self.witness.enroll(operator_confirmed=True)
        self.advance()
        with self.assertRaisesRegex(IdentityPinError,'STALE'):
            self.witness.publish(operator_confirmed=True,expected_count=0,expected_last_mac='0'*64)
    def test_replay(self):
        self.witness.enroll(operator_confirmed=True)
        with self.assertRaisesRegex(IdentityPinError,'REPLAY'):
            self.witness.publish(operator_confirmed=True,expected_count=0,expected_last_mac='0'*64)
    def test_tamper(self):
        self.witness.enroll(operator_confirmed=True)
        data=json.loads(self.witness.path.read_text())
        data['entries'][0]['count']=100
        self.witness.path.write_text(json.dumps(data))
        with self.assertRaisesRegex(IdentityPinError,'INVALID'):self.witness.verify()
    def test_wrong_key(self):
        self.witness.enroll(operator_confirmed=True)
        other=ExternalReviewWitness(self.anchor,witness_path=self.witness.path,key=b'x'*32)
        with self.assertRaisesRegex(IdentityPinError,'INVALID'):other.verify()
    def test_symlink(self):
        link=self.path.parent/'witness-link'
        link.symlink_to(self.anchor.path)
        with self.assertRaisesRegex(IdentityPinError,'UNSAFE'):
            ExternalReviewWitness(self.anchor,witness_path=link,key=b'w'*32)
    def test_no_repair(self):
        self.witness.enroll(operator_confirmed=True)
        self.advance()
        self.witness.restoration_report()
        self.assertEqual(json.loads(self.witness.path.read_text())['entries'][-1]['count'],0)
