"""Dual-HMAC rollover regressions in an isolated POSIX local laboratory.

No NAS, no production state, no secrets in repository. Author: Abdelhalim Talbi.
"""
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lease_registry import initialize as init_leases, claim
from odmm_linux_datamover_intents import initialize, quarantine_unfinished
from odmm_linux_lab_pipeline import run_lab_copy, LabPipelineError
from odmm_linux_lab_external_anchor import create_anchor, AnchorError
from odmm_linux_lab_anchor_rotation import create_rotation, verify_rotation


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX local lab only")
class RotationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = sqlite3.connect(self.root / "journal.db", isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        init_leases(self.db)
        initialize(self.db)
        token = claim(self.db, "task", "worker", 100, now=100)
        source = self.root / "source" / "data"
        target = self.root / "target" / "data"
        source.parent.mkdir()
        target.parent.mkdir()
        source.write_bytes(b"rotation-test" * 1024)
        self.anchor_dir = self.root / "anchors"
        self.anchor_dir.mkdir()
        self.old = b"lab-only-old-key-" + b"a" * 40
        self.new = b"lab-only-new-key-" + b"b" * 40
        with self.assertRaisesRegex(LabPipelineError, "INJECTED_AFTER_IDENTITY_EVIDENCE"):
            run_lab_copy(self.db, intent_id="copy", task_id="task", owner="worker",
                         token=token, source=source, target=target, now=101,
                         fault_at="after_identity_evidence")
        self.assertEqual(quarantine_unfinished(self.db, now=102), 1)
        create_anchor(self.db, "copy", self.anchor_dir,
                      key_id="old", secret=self.old)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def rotate(self):
        return create_rotation(self.db, "copy", self.anchor_dir,
                               from_key_id="old", to_key_id="new",
                               old_secret=self.old, new_secret=self.new)

    def verify(self, status=None, resolver=None):
        if status is None:
            status = lambda key: "retired" if key == "old" else "active"
        if resolver is None:
            resolver = lambda key: {"old": self.old, "new": self.new}[key]
        return verify_rotation(self.db, "copy", self.anchor_dir,
                               from_key_id="old", to_key_id="new",
                               key_resolver=resolver, key_status=status)

    def test_dual_signature_and_quarantine_unchanged(self):
        self.assertTrue(self.rotate()["rotation_recorded"])
        result = self.verify()
        self.assertTrue(result["authenticated"])
        self.assertFalse(result["authorizes_resume"])
        self.assertEqual(self.db.execute(
            "SELECT state FROM odmm_datamover_intents WHERE intent_id='copy'"
        ).fetchone()[0], "UNCERTAIN")

    def test_duplicate_receipt_cannot_overwrite(self):
        self.rotate()
        with self.assertRaises(FileExistsError):
            self.rotate()
        self.assertTrue(self.verify()["authenticated"])

    def test_rotated_receipt_does_not_survive_evidence_mutation(self):
        self.rotate()
        self.db.execute(
            "UPDATE odmm_datamover_intents SET owner=? WHERE intent_id=?",
            ("unexpected-owner", "copy"),
        )
        self.assertFalse(self.verify()["authenticated"])
        self.assertEqual(self.db.execute(
            "SELECT state FROM odmm_datamover_intents WHERE intent_id='copy'"
        ).fetchone()[0], "UNCERTAIN")

    def test_new_key_retired_fails_closed(self):
        self.rotate()
        self.assertFalse(self.verify(
            status=lambda key: "retired"
        )["authenticated"])

    def test_missing_receipt_fails_closed(self):
        self.assertFalse(self.verify()["authenticated"])

    def test_wrong_new_key_fails_closed(self):
        self.rotate()
        self.assertFalse(self.verify(resolver=lambda key: self.old if key == "old"
                                     else b"x" * 48)["authenticated"])

    def test_wrong_old_key_fails_closed(self):
        self.rotate()
        self.assertFalse(self.verify(resolver=lambda key: self.new if key == "new"
                                     else b"x" * 48)["authenticated"])

    def test_revoked_old_or_new_key_fails_closed(self):
        self.rotate()
        for revoked in ("old", "new"):
            with self.subTest(revoked=revoked):
                self.assertFalse(self.verify(
                    status=lambda key: "revoked" if key == revoked else "active"
                )["authenticated"])

    def test_tampered_receipt_fails_closed(self):
        self.rotate()
        receipt = next(self.anchor_dir.glob("*.rotation.json"))
        doc = json.loads(receipt.read_text())
        doc["evidence_sha256"] = "0" * 64
        receipt.write_text(json.dumps(doc))
        self.assertFalse(self.verify()["authenticated"])

    def test_receipt_symlink_fails_closed(self):
        self.rotate()
        receipt = next(self.anchor_dir.glob("*.rotation.json"))
        parked = self.root / "parked-receipt"
        receipt.rename(parked)
        receipt.symlink_to(parked)
        self.assertFalse(self.verify()["authenticated"])

    def test_key_provider_failure_fails_closed(self):
        self.rotate()
        def down(_):
            raise RuntimeError("external vault unavailable")
        self.assertFalse(self.verify(resolver=down)["authenticated"])

    def test_old_key_mismatch_rejects_creation(self):
        with self.assertRaisesRegex(AnchorError, "ORIGINAL_ANCHOR_NOT_AUTHENTICATED"):
            create_rotation(self.db, "copy", self.anchor_dir,
                            from_key_id="old", to_key_id="new",
                            old_secret=b"x" * 48, new_secret=self.new)
        self.assertFalse(any(self.anchor_dir.glob("*.rotation.json")))

    def test_invalid_key_ids_rejected(self):
        with self.assertRaisesRegex(AnchorError, "INVALID_ROTATION_KEY_IDS"):
            create_rotation(self.db, "copy", self.anchor_dir,
                            from_key_id="old", to_key_id="../bad",
                            old_secret=self.old, new_secret=self.new)


if __name__ == "__main__":
    unittest.main()
