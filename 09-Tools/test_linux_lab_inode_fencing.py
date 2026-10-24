"""POSIX local lab: reject inode substitution and pathname chmod attacks.

These tests are deterministic local filesystem injections, NOT real NAS tests.
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
class InodeFenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = sqlite3.connect(self.root / "journal.db", isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        init_leases(self.db)
        initialize(self.db)
        self.token = claim(self.db, "job", "node", 100, now=100)
        self.src = self.root / "source"
        self.dst = self.root / "target"
        self.src.write_bytes(b"nas-lab" * 8192)
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

    def test_target_symlink_swap_never_chmods_victim(self):
        victim = self.root / "unrelated"
        victim.write_bytes(b"keep-me")
        os.chmod(victim, 0o700)

        def swap_after_copy(inp, out, **kwargs):
            self.original_copy(inp, out, **kwargs)
            self.dst.unlink()
            self.dst.symlink_to(victim)

        with patch("odmm_linux_lab_pipeline.shutil.copyfileobj",
                   side_effect=swap_after_copy):
            with self.assertRaisesRegex(LabPipelineError, "TARGET_PATH_CHANGED"):
                self.run_copy()
        self.assertEqual(victim.read_bytes(), b"keep-me")
        self.assertEqual(victim.stat().st_mode & 0o777, 0o700)
        self.assertTrue(self.dst.is_symlink())
        self.assert_quarantined()

    def test_matching_replacement_target_cannot_be_verified(self):
        data = self.src.read_bytes()

        def replace_after_copy(inp, out, **kwargs):
            self.original_copy(inp, out, **kwargs)
            self.dst.unlink()
            self.dst.write_bytes(data)
            os.chmod(self.dst, 0o640)

        with patch("odmm_linux_lab_pipeline.shutil.copyfileobj",
                   side_effect=replace_after_copy):
            with self.assertRaisesRegex(LabPipelineError, "TARGET_PATH_CHANGED"):
                self.run_copy()
        self.assertEqual(self.dst.read_bytes(), data)
        self.assert_quarantined()

    def test_matching_replacement_source_cannot_be_verified(self):
        data = self.src.read_bytes()

        def replace_after_copy(inp, out, **kwargs):
            self.original_copy(inp, out, **kwargs)
            self.src.unlink()
            self.src.write_bytes(data)
            os.chmod(self.src, 0o640)

        with patch("odmm_linux_lab_pipeline.shutil.copyfileobj",
                   side_effect=replace_after_copy):
            with self.assertRaisesRegex(LabPipelineError, "SOURCE_PATH_CHANGED"):
                self.run_copy()
        self.assertEqual(self.dst.read_bytes(), data)
        self.assert_quarantined()

    def test_original_inodes_complete_successfully(self):
        result = self.run_copy()
        self.assertEqual(result["state"], "VERIFIED")
        self.assertEqual(self.dst.read_bytes(), self.src.read_bytes())
        self.assertEqual(self.dst.stat().st_mode & 0o777, 0o640)
        self.assertEqual(unresolved(self.db), [])


if __name__ == "__main__":
    unittest.main()
