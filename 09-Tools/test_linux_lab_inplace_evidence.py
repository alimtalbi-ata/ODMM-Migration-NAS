"""Regression tests for inode-preserving content mutation during UNCERTAIN inspection.

Scope: Linux local POSIX laboratory; never authorizes automatic recovery.
Author: Abdelhalim Talbi.
"""
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
from odmm_linux_lab_identity_journal import inspect_identity
from odmm_linux_lab_reconciliation import inspect_uncertain


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX laboratory only")
class InPlaceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = sqlite3.connect(root / "state.db", isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        init_leases(self.db)
        initialize(self.db)
        token = claim(self.db, "task", "worker", 100, now=100)
        srcdir, dstdir = root / "source", root / "target"
        srcdir.mkdir()
        dstdir.mkdir()
        self.source, self.target = srcdir / "data.bin", dstdir / "data.bin"
        self.source.write_bytes(b"original-contents" * 128)
        with self.assertRaisesRegex(LabPipelineError, "INJECTED_AFTER_IDENTITY_EVIDENCE"):
            run_lab_copy(self.db, intent_id="copy", task_id="task", owner="worker",
                         token=token, source=self.source, target=self.target,
                         now=101, fault_at="after_identity_evidence")
        self.assertEqual(quarantine_unfinished(self.db, now=102), 1)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_unchanged_files_still_match_but_never_authorize_resume(self):
        evidence = inspect_identity(self.db, "copy", self.source, self.target)
        self.assertTrue(evidence["identity_matches"])
        self.assertFalse(evidence["authorizes_resume"])
        self.assertFalse(evidence["nas_migration_qualified"])

    def test_target_same_size_in_place_mutation_is_detected(self):
        inode = self.target.stat().st_ino
        with self.target.open("r+b") as f:
            f.seek(0)
            f.write(b"X")
            f.flush()
            os.fsync(f.fileno())
        self.assertEqual(self.target.stat().st_ino, inode)
        evidence = inspect_identity(self.db, "copy", self.source, self.target)
        self.assertFalse(evidence["identity_matches"])
        self.assertEqual(evidence["reason"], "CONTENT_DIGEST_MISMATCH")
        report = inspect_uncertain(self.db, "copy", self.source, self.target)
        self.assertEqual(report["decision"], "MANUAL_REVIEW_REQUIRED")
        self.assertEqual(report["identity_evidence"]["reason"], "CONTENT_DIGEST_MISMATCH")
        self.assertEqual(self.db.execute(
            "SELECT state FROM odmm_datamover_intents WHERE intent_id='copy'").fetchone()[0],
            "UNCERTAIN")

    def test_source_same_size_in_place_mutation_is_detected(self):
        inode = self.source.stat().st_ino
        with self.source.open("r+b") as f:
            f.seek(1)
            f.write(b"Z")
            f.flush()
            os.fsync(f.fileno())
        self.assertEqual(self.source.stat().st_ino, inode)
        evidence = inspect_identity(self.db, "copy", self.source, self.target)
        self.assertFalse(evidence["identity_matches"])
        self.assertEqual(evidence["reason"], "CONTENT_DIGEST_MISMATCH")

    def test_truncation_is_detected_even_with_original_inode(self):
        inode = self.target.stat().st_ino
        with self.target.open("r+b") as f:
            f.truncate(12)
            f.flush()
            os.fsync(f.fileno())
        self.assertEqual(self.target.stat().st_ino, inode)
        evidence = inspect_identity(self.db, "copy", self.source, self.target)
        self.assertFalse(evidence["identity_matches"])
        self.assertEqual(evidence["reason"], "CONTENT_SIZE_CHANGED")


if __name__ == "__main__":
    unittest.main()
