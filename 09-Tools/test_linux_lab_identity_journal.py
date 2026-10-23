"""Durable inode evidence tests: local Linux POSIX lab, never production NAS.

Author: Abdelhalim Talbi.
"""
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lease_registry import initialize as init_leases, claim
from odmm_linux_datamover_intents import initialize, quarantine_unfinished
from odmm_linux_lab_pipeline import run_lab_copy, LabPipelineError
from odmm_linux_lab_reconciliation import inspect_uncertain
from odmm_linux_lab_identity_journal import (
    inspect_identity, record_identity, IdentityEvidenceConflict,
)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX laboratory only")
class IdentityJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = sqlite3.connect(self.root / "journal.db", isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        init_leases(self.db)
        initialize(self.db)
        self.token = claim(self.db, "task", "worker", 100, now=100)
        self.source_dir = self.root / "source"
        self.target_dir = self.root / "target"
        self.source_dir.mkdir()
        self.target_dir.mkdir()
        self.src = self.source_dir / "file.bin"
        self.dst = self.target_dir / "file.bin"
        self.src.write_bytes(b"evidence" * 8192)
        os.chmod(self.src, 0o640)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def run_copy(self, fault_at=None):
        return run_lab_copy(self.db, intent_id="copy", task_id="task",
                            owner="worker", token=self.token,
                            source=self.src, target=self.dst, now=101,
                            fault_at=fault_at)

    def crash_after_observation(self):
        with self.assertRaisesRegex(LabPipelineError, "INJECTED_AFTER_IDENTITY_EVIDENCE"):
            self.run_copy(fault_at="after_identity_evidence")
        self.assertEqual(quarantine_unfinished(self.db, now=102), 1)

    def test_verified_copy_has_immutable_durable_evidence(self):
        self.assertEqual(self.run_copy()["state"], "VERIFIED")
        proof = inspect_identity(self.db, "copy", self.src, self.dst)
        self.assertTrue(proof["recorded"])
        self.assertTrue(proof["identity_matches"])
        self.assertFalse(proof["authorizes_resume"])
        self.assertFalse(proof["nas_migration_qualified"])

    def test_crash_after_observation_stays_uncertain_despite_matching_bytes(self):
        self.crash_after_observation()
        report = inspect_uncertain(self.db, "copy", self.src, self.dst)
        self.assertTrue(report["content_verified"])
        self.assertTrue(report["identity_evidence"]["identity_matches"])
        self.assertEqual(report["decision"], "MANUAL_REVIEW_REQUIRED")
        self.assertEqual(self.db.execute(
            "SELECT state FROM odmm_datamover_intents WHERE intent_id='copy'").fetchone()[0], "UNCERTAIN")

    def test_same_content_target_replacement_is_detected(self):
        self.crash_after_observation()
        data = self.dst.read_bytes()
        mode = stat.S_IMODE(self.dst.stat().st_mode)
        # Retain the old inode to prevent filesystem inode-number reuse.
        self.dst.rename(self.target_dir / 'parked-original-target')
        self.dst.write_bytes(data)
        os.chmod(self.dst, mode)
        report = inspect_uncertain(self.db, "copy", self.src, self.dst)
        self.assertTrue(report["content_verified"])
        self.assertFalse(report["identity_evidence"]["identity_matches"])
        self.assertEqual(report["identity_evidence"]["reason"], "PATH_IDENTITY_CHANGED")

    def test_same_content_source_replacement_is_detected(self):
        self.crash_after_observation()
        data = self.src.read_bytes()
        # Retain the old inode so this is a deterministic replacement.
        self.src.rename(self.source_dir / 'parked-original-source')
        self.src.write_bytes(data)
        os.chmod(self.src, 0o640)
        report = inspect_uncertain(self.db, "copy", self.src, self.dst)
        self.assertTrue(report["content_verified"])
        self.assertFalse(report["identity_evidence"]["identity_matches"])

    def test_crash_before_observation_has_no_claimed_proof(self):
        with self.assertRaisesRegex(LabPipelineError, "INJECTED_AFTER_COPY_FSYNC"):
            self.run_copy(fault_at="after_copy_fsync")
        self.assertEqual(quarantine_unfinished(self.db, now=102), 1)
        report = inspect_uncertain(self.db, "copy", self.src, self.dst)
        self.assertFalse(report["identity_evidence"]["recorded"])
        self.assertIsNone(report["identity_evidence"]["identity_matches"])

    def test_duplicate_observation_is_immutable(self):
        self.run_copy()
        row = self.db.execute("""SELECT payload_sha256,observation_json FROM
            odmm_lab_identity_evidence WHERE intent_id='copy'""").fetchone()
        with self.assertRaises(IdentityEvidenceConflict):
            record_identity(self.db, intent_id="copy", task_id="task", owner="worker",
                            token=self.token, payload_sha256=row[0],
                            observation=json.loads(row[1]), now=102)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM odmm_lab_identity_evidence").fetchone()[0], 1)

    def test_tampered_observation_digest_fails_closed(self):
        self.crash_after_observation()
        self.db.execute("""UPDATE odmm_lab_identity_evidence SET
            observation_json='{}' WHERE intent_id='copy'""")
        proof = inspect_identity(self.db, "copy", self.src, self.dst)
        self.assertFalse(proof["identity_matches"])
        self.assertEqual(proof["reason"], "JOURNAL_DIGEST_MISMATCH")

    def test_missing_target_is_not_an_identity_match(self):
        self.crash_after_observation()
        self.dst.unlink()
        report = inspect_uncertain(self.db, "copy", self.src, self.dst)
        self.assertEqual(report["reason"], "TARGET_ABSENT")
        self.assertFalse(report["identity_evidence"]["identity_matches"])


if __name__ == "__main__":
    unittest.main()
