"""External HMAC anchor regressions; isolated Linux POSIX lab only.

No real NAS operations. Author: Abdelhalim Talbi.
"""
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lease_registry import initialize as init_leases, claim
from odmm_linux_datamover_intents import initialize, quarantine_unfinished
from odmm_linux_lab_pipeline import run_lab_copy, LabPipelineError
from odmm_linux_lab_external_anchor import create_anchor, verify_anchor, AnchorError
from odmm_linux_lab_reconciliation import inspect_uncertain


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux local POSIX lab only")
class ExternalAnchorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = sqlite3.connect(self.root / "journal.db", isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        init_leases(self.db)
        initialize(self.db)
        token = claim(self.db, "task", "worker", 100, now=100)
        self.source = self.root / "source" / "data.bin"
        self.target = self.root / "target" / "data.bin"
        self.source.parent.mkdir()
        self.target.parent.mkdir()
        self.source.write_bytes(b"anchor" * 4096)
        self.anchor_dir = self.root / "independent-anchor"
        self.anchor_dir.mkdir()
        self.secret = b"test-only-ephemeral-not-for-production!" + b"x" * 16
        with self.assertRaisesRegex(LabPipelineError, "INJECTED_AFTER_IDENTITY_EVIDENCE"):
            run_lab_copy(self.db, intent_id="copy", task_id="task", owner="worker",
                         token=token, source=self.source, target=self.target,
                         now=101, fault_at="after_identity_evidence")
        self.assertEqual(quarantine_unfinished(self.db, now=102), 1)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def anchor(self):
        return create_anchor(self.db, "copy", self.anchor_dir,
                             key_id="lab-key-1", secret=self.secret)

    def verify(self, resolver=None):
        if resolver is None:
            resolver = lambda key_id: self.secret if key_id == "lab-key-1" else None
        return verify_anchor(self.db, "copy", self.anchor_dir, key_resolver=resolver)

    def test_valid_external_anchor_never_promotes_uncertain(self):
        proof = self.anchor()
        self.assertTrue(proof["anchored"])
        self.assertFalse(proof["authorizes_resume"])
        self.assertTrue(self.verify()["authenticated"])
        self.assertEqual(inspect_uncertain(self.db, "copy", self.source, self.target)["decision"],
                         "MANUAL_REVIEW_REQUIRED")
        self.assertEqual(self.db.execute(
            "SELECT state FROM odmm_datamover_intents WHERE intent_id='copy'").fetchone()[0],
            "UNCERTAIN")

    def test_duplicate_anchor_cannot_overwrite(self):
        self.anchor()
        with self.assertRaises(FileExistsError):
            self.anchor()
        self.assertTrue(self.verify()["authenticated"])

    def test_missing_anchor_fails_closed(self):
        self.assertFalse(self.verify()["authenticated"])

    def test_wrong_external_key_fails_closed(self):
        self.anchor()
        self.assertFalse(self.verify(lambda _: b"wrong-key" * 8)["authenticated"])

    def test_tampered_anchor_fails_closed(self):
        self.anchor()
        path = next(self.anchor_dir.iterdir())
        document = json.loads(path.read_text())
        document["evidence"]["task_id"] = "attacker"
        path.write_text(json.dumps(document))
        self.assertFalse(self.verify()["authenticated"])

    def test_rehashed_sqlite_tampering_detected_by_hmac(self):
        self.anchor()
        altered = '{"attacker":true}'
        digest = hashlib.sha256(altered.encode()).hexdigest()
        self.db.execute("""UPDATE odmm_lab_identity_evidence
            SET observation_json=?, observation_sha256=? WHERE intent_id='copy'""",
            (altered, digest))
        result = self.verify()
        self.assertFalse(result["authenticated"])
        self.assertEqual(result["reason"], "ANCHOR_MISSING_UNSAFE_OR_MISMATCH")

    def test_symlink_anchor_refused(self):
        self.anchor()
        path = next(self.anchor_dir.iterdir())
        parked = self.root / "parked-anchor"
        path.rename(parked)
        path.symlink_to(parked)
        self.assertFalse(self.verify()["authenticated"])

    def test_symlink_anchor_directory_refused(self):
        self.anchor()
        other = self.root / "parked-directory"
        self.anchor_dir.rename(other)
        self.anchor_dir.symlink_to(other, target_is_directory=True)
        self.assertFalse(self.verify()["authenticated"])

    def test_unknown_or_short_secret_refused(self):
        with self.assertRaises(AnchorError):
            create_anchor(self.db, "copy", self.anchor_dir,
                          key_id="lab-key-1", secret=b"short")
        self.assertFalse(self.verify()["authenticated"])


if __name__ == "__main__":
    unittest.main()
