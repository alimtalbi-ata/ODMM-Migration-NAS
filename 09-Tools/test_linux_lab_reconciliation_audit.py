"""Operator review audit remains append-only and cannot resume a transfer."""
import sqlite3
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_datamover_intents import initialize as init_intents
from odmm_linux_lab_reconciliation_audit import initialize, record_review, verify_review, ReviewConflict
from odmm_linux_lab_review_identity import issue_assertion

class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        init_intents(self.db)
        initialize(self.db)
        self.db.execute("""INSERT INTO odmm_datamover_intents
            (intent_id,task_id,owner,fence_token,payload_sha256,state,created_at,updated_at)
            VALUES ('i','task','worker',1,?,'UNCERTAIN',1,1)""", ("a"*64,))
        self.secret = b"review-lab-test-secret-with-at-least-32-bytes"
        self.evidence = {"intent_id": "i", "state": "UNCERTAIN",
                         "decision": "MANUAL_REVIEW_REQUIRED", "reason": "TARGET_ABSENT"}

    def _assertion(self, role):
        return issue_assertion(self.secret, operator_id="operator", role=role, issued_at=9, ttl=30)

    def tearDown(self):
        self.db.close()

    def test_review_preserves_uncertain_and_fingerprint(self):
        result = record_review(self.db, review_id="r1", intent_id="i",
            operator_id="operator", decision="HOLD", role="reviewer", identity_assertion=self._assertion("reviewer"), signing_secret=self.secret, evidence=self.evidence, now=10)
        self.assertEqual(len(result["evidence_sha256"]), 64)
        self.assertEqual(result["state_after"], "UNCERTAIN")
        self.assertEqual(self.db.execute("SELECT state FROM odmm_datamover_intents").fetchone()[0], "UNCERTAIN")

    def test_evidence_fingerprint_detects_tampering(self):
        record_review(self.db, review_id="r1", intent_id="i", operator_id="operator",
                      decision="REQUEST_RECHECK", role="reviewer", identity_assertion=self._assertion("reviewer"), signing_secret=self.secret, evidence=self.evidence, now=10)
        valid = verify_review(self.db, "r1", self.evidence)
        self.assertTrue(valid["evidence_matches"])
        self.assertFalse(valid["authorizes_resume"])
        changed = {**self.evidence, "reason": "ALTERED"}
        self.assertFalse(verify_review(self.db, "r1", changed)["evidence_matches"])
        with self.assertRaisesRegex(ReviewConflict, "UNKNOWN_REVIEW"):
            verify_review(self.db, "missing", self.evidence)

    def test_duplicate_review_rejected(self):
        args = dict(review_id="r1", intent_id="i", operator_id="operator",
                    decision="ESCALATE", role="incident_lead", identity_assertion=self._assertion("incident_lead"), signing_secret=self.secret, evidence=self.evidence, now=10)
        record_review(self.db, **args)
        with self.assertRaisesRegex(ReviewConflict, "DUPLICATE_REVIEW_ID"):
            record_review(self.db, **args)
        self.assertEqual(self.db.execute("SELECT count(*) FROM odmm_reconciliation_reviews").fetchone()[0], 1)

    def test_unverified_identity_refused(self):
        with self.assertRaisesRegex(PermissionError, "UNTRUSTED_SIGNING_KEY"):
            record_review(self.db, review_id="r1", intent_id="i", operator_id="operator",
                          decision="HOLD", role="reviewer", evidence=self.evidence, now=10)
        self.assertEqual(self.db.execute("SELECT count(*) FROM odmm_reconciliation_reviews").fetchone()[0], 0)

    def test_observer_cannot_write_review(self):
        with self.assertRaisesRegex(PermissionError, "DECISION_NOT_AUTHORIZED"):
            record_review(self.db, review_id="r1", intent_id="i", operator_id="operator",
                          decision="HOLD", role="observer", identity_assertion=self._assertion("observer"), signing_secret=self.secret,
                          evidence=self.evidence, now=10)

    def test_approval_decision_refused(self):
        with self.assertRaisesRegex(PermissionError, "DECISION_NOT_AUTHORIZED"):
            record_review(self.db, review_id="r1", intent_id="i", operator_id="operator",
                          decision="APPROVE_RESUME", role="incident_lead", identity_assertion=self._assertion("incident_lead"), signing_secret=self.secret, evidence=self.evidence, now=10)

if __name__ == "__main__":
    unittest.main()
