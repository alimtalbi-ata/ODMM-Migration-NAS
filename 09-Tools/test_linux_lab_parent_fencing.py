"""Deterministic POSIX lab regressions for pinned parent directory identity.

These tests do not qualify NFS/SMB or production multiserver fencing.
Author: Abdelhalim Talbi.
"""
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lease_registry import initialize as init_leases, claim
from odmm_linux_datamover_intents import initialize, quarantine_unfinished, unresolved
from odmm_linux_lab_pipeline import run_lab_copy, LabPipelineError


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX laboratory only")
class ParentDirectoryFenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = sqlite3.connect(self.root / "journal.db", isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        init_leases(self.db)
        initialize(self.db)
        self.token = claim(self.db, "job", "node", 100, now=100)
        self.source_dir = self.root / "source-dir"
        self.target_dir = self.root / "target-dir"
        self.source_dir.mkdir()
        self.target_dir.mkdir()
        self.src = self.source_dir / "source"
        self.dst = self.target_dir / "target"
        self.src.write_bytes(b"nas-lab" * 4096)
        os.chmod(self.src, 0o640)
        self.original_copy = shutil.copyfileobj

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def run_copy(self):
        return run_lab_copy(self.db, intent_id="copy-1", task_id="job",
                            owner="node", token=self.token, source=self.src,
                            target=self.dst, now=101)

    def assert_quarantined(self):
        self.assertEqual(unresolved(self.db)[0][-1], "IN_FLIGHT")
        self.assertEqual(quarantine_unfinished(self.db, now=102), 1)
        self.assertEqual(unresolved(self.db)[0][-1], "UNCERTAIN")

    def test_original_parent_descriptors_succeed(self):
        result = self.run_copy()
        self.assertEqual(result["state"], "VERIFIED")
        self.assertEqual(self.src.read_bytes(), self.dst.read_bytes())
        self.assertEqual(unresolved(self.db), [])

    def test_target_parent_replaced_by_directory_fails_closed(self):
        parked = self.root / "parked-target"
        def swap(inp, out, **kwargs):
            self.original_copy(inp, out, **kwargs)
            self.target_dir.rename(parked)
            self.target_dir.mkdir()
        with patch("odmm_linux_lab_pipeline.shutil.copyfileobj", side_effect=swap):
            with self.assertRaisesRegex(LabPipelineError, "TARGET_PARENT_CHANGED"):
                self.run_copy()
        self.assertFalse(self.dst.exists())
        self.assertEqual((parked / "target").read_bytes(), self.src.read_bytes())
        self.assert_quarantined()

    def test_target_parent_replaced_by_symlink_never_writes_victim(self):
        parked = self.root / "parked-target"
        victim = self.root / "unrelated"
        victim.mkdir()
        (victim / "sentinel").write_bytes(b"untouched")
        def swap(inp, out, **kwargs):
            self.original_copy(inp, out, **kwargs)
            self.target_dir.rename(parked)
            self.target_dir.symlink_to(victim, target_is_directory=True)
        with patch("odmm_linux_lab_pipeline.shutil.copyfileobj", side_effect=swap):
            with self.assertRaisesRegex(LabPipelineError, "TARGET_PARENT_CHANGED"):
                self.run_copy()
        self.assertFalse((victim / "target").exists())
        self.assertEqual((victim / "sentinel").read_bytes(), b"untouched")
        self.assertTrue((parked / "target").exists())
        self.assert_quarantined()

    def test_source_parent_replaced_by_matching_directory_fails_closed(self):
        parked = self.root / "parked-source"
        data = self.src.read_bytes()
        def swap(inp, out, **kwargs):
            self.original_copy(inp, out, **kwargs)
            self.source_dir.rename(parked)
            self.source_dir.mkdir()
            self.src.write_bytes(data)
            os.chmod(self.src, 0o640)
        with patch("odmm_linux_lab_pipeline.shutil.copyfileobj", side_effect=swap):
            with self.assertRaisesRegex(LabPipelineError, "SOURCE_PARENT_CHANGED"):
                self.run_copy()
        self.assert_quarantined()

    def test_initial_symlink_parent_refused_before_intent(self):
        victim = self.root / "unrelated"
        victim.mkdir()
        self.target_dir.rmdir()
        self.target_dir.symlink_to(victim, target_is_directory=True)
        with self.assertRaisesRegex(LabPipelineError, "PARENT_SYMLINK_REFUSED"):
            self.run_copy()
        self.assertEqual(unresolved(self.db), [])
        self.assertFalse((victim / "target").exists())


if __name__ == "__main__":
    unittest.main()
