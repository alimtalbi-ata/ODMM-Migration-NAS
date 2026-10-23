"""Crash-window and orphan inspection tests; isolated local Linux POSIX only.

The SIGKILL tests terminate only disposable subprocesses. No NAS access.
Author: Abdelhalim Talbi.
"""
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02-Sources"))
from odmm_linux_lease_registry import initialize as init_leases, claim
from odmm_linux_datamover_intents import initialize, quarantine_unfinished
from odmm_linux_lab_pipeline import run_lab_copy, LabPipelineError
from odmm_linux_lab_external_anchor import create_anchor
from odmm_linux_lab_anchor_rotation import create_rotation, verify_rotation
from odmm_linux_lab_rotation_recovery import inspect_rotation_publication


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX lab only")
class RotationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_path = self.root / "journal.db"
        self.db = sqlite3.connect(self.db_path, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        init_leases(self.db)
        initialize(self.db)
        token = claim(self.db, "task", "worker", 100, now=100)
        src, dst = self.root / "src" / "data", self.root / "dst" / "data"
        src.parent.mkdir()
        dst.parent.mkdir()
        src.write_bytes(b"rotation-crash" * 2048)
        self.anchors = self.root / "anchors"
        self.anchors.mkdir()
        self.old = b"lab-only-old-key-" + b"a" * 40
        self.new = b"lab-only-new-key-" + b"b" * 40
        with self.assertRaisesRegex(LabPipelineError, "INJECTED_AFTER_IDENTITY_EVIDENCE"):
            run_lab_copy(self.db, intent_id="copy", task_id="task", owner="worker",
                         token=token, source=src, target=dst, now=101,
                         fault_at="after_identity_evidence")
        self.assertEqual(quarantine_unfinished(self.db, now=102), 1)
        create_anchor(self.db, "copy", self.anchors, key_id="old", secret=self.old)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def inspect(self):
        return inspect_rotation_publication(self.anchors, "copy", "new")

    def verify(self):
        return verify_rotation(
            self.db, "copy", self.anchors, from_key_id="old", to_key_id="new",
            key_resolver=lambda key: {"old": self.old, "new": self.new}[key],
            key_status=lambda key: "retired" if key == "old" else "active")

    def rotate(self):
        return create_rotation(self.db, "copy", self.anchors,
                               from_key_id="old", to_key_id="new",
                               old_secret=self.old, new_secret=self.new)

    def test_clean_receipt_still_requires_cryptographic_authentication(self):
        self.rotate()
        self.assertEqual(self.inspect()["status"], "FINAL_PRESENT_UNVERIFIED")
        self.assertTrue(self.inspect()["ready_for_authentication"])
        self.assertTrue(self.verify()["authenticated"])
        self.assertFalse(self.inspect()["authorizes_resume"])

    def test_absent_receipt_never_authenticates(self):
        self.assertEqual(self.inspect()["status"], "ABSENT")
        self.assertFalse(self.verify()["authenticated"])

    def test_unrelated_pending_blocks_even_valid_final_receipt(self):
        self.rotate()
        final = next(self.anchors.glob("*.rotation.json"))
        pending = self.anchors / (final.name + ".pending-" + "a" * 32)
        pending.write_bytes(b"{}")
        pending.chmod(0o600)
        self.assertEqual(self.inspect()["status"], "UNRELATED_PENDING")
        self.assertFalse(self.verify()["authenticated"])

    def test_hardlinked_pending_blocks_final_receipt(self):
        self.rotate()
        final = next(self.anchors.glob("*.rotation.json"))
        os.link(final, self.anchors / (final.name + ".pending-" + "b" * 32))
        self.assertEqual(self.inspect()["status"], "PUBLISHED_WITH_PENDING")
        self.assertFalse(self.verify()["authenticated"])

    def test_symlink_pending_fails_closed_without_following(self):
        self.rotate()
        final = next(self.anchors.glob("*.rotation.json"))
        (self.anchors / (final.name + ".pending-" + "c" * 32)).symlink_to(final)
        self.assertEqual(self.inspect()["status"], "UNSAFE_OR_UNAVAILABLE")
        self.assertFalse(self.verify()["authenticated"])

    def test_malformed_pending_filename_fails_closed(self):
        self.rotate()
        final = next(self.anchors.glob("*.rotation.json"))
        (self.anchors / (final.name + ".pending-invalid")).write_bytes(b"x")
        self.assertEqual(self.inspect()["status"], "UNSAFE_OR_UNAVAILABLE")
        self.assertFalse(self.verify()["authenticated"])

    def test_pending_hardlink_to_external_file_fails_closed(self):
        final_name = _receipt_name("copy", "new")
        outside = self.root / "outside-receipt"
        outside.write_bytes(b"untrusted")
        outside.chmod(0o600)
        os.link(outside, self.anchors / (final_name + ".pending-" + "d" * 32))
        self.assertEqual(self.inspect()["status"], "UNSAFE_OR_UNAVAILABLE")
        self.assertFalse(self.verify()["authenticated"])

    def test_world_readable_final_receipt_fails_closed(self):
        self.rotate()
        final = next(self.anchors.glob("*.rotation.json"))
        final.chmod(0o644)
        self.assertEqual(self.inspect()["status"], "UNSAFE_OR_UNAVAILABLE")
        self.assertFalse(self.verify()["authenticated"])

    def test_many_pending_files_fail_closed(self):
        self.rotate()
        final = next(self.anchors.glob("*.rotation.json"))
        for n in range(33):
            p = self.anchors / (final.name + ".pending-" + f"{n:032x}")
            p.write_bytes(b"x")
            p.chmod(0o600)
        self.assertEqual(self.inspect()["status"], "UNSAFE_OR_UNAVAILABLE")
        self.assertFalse(self.verify()["authenticated"])

    def _sigkill(self, boundary):
        child = textwrap.dedent("""
            import os, signal, sqlite3, sys
            import odmm_linux_lab_anchor_rotation as rotation
            db = sqlite3.connect(sys.argv[1], isolation_level=None)
            boundary = sys.argv[3]
            def stop():
                print("ROTATION_BOUNDARY_" + boundary, flush=True)
                os.kill(os.getpid(), signal.SIGKILL)
            original_link = rotation.os.link
            def link(*args, **kwargs):
                if boundary == "before_link":
                    stop()
                result = original_link(*args, **kwargs)
                if boundary == "after_link":
                    stop()
                return result
            rotation.os.link = link
            original_fsync = rotation.os.fsync
            def fsync(fd):
                result = original_fsync(fd)
                if boundary == "after_stage_fsync":
                    stop()
                return result
            rotation.os.fsync = fsync
            rotation.create_rotation(
                db, "copy", sys.argv[2], from_key_id="old", to_key_id="new",
                old_secret=b"lab-only-old-key-" + b"a" * 40,
                new_secret=b"lab-only-new-key-" + b"b" * 40)
        """)
        proc = subprocess.run(
            [sys.executable, "-c", child, str(self.db_path), str(self.anchors), boundary],
            cwd=self.root, env={**os.environ, "PYTHONPATH": str(ROOT / "02-Sources")},
            capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(proc.returncode, -signal.SIGKILL, proc.stderr)
        self.assertIn("ROTATION_BOUNDARY_" + boundary, proc.stdout)
        result = self.inspect()
        self.assertFalse(result["ready_for_authentication"])
        self.assertFalse(result["authorizes_resume"])
        self.assertFalse(self.verify()["authenticated"])
        self.assertEqual(self.db.execute(
            "SELECT state FROM odmm_datamover_intents WHERE intent_id='copy'"
        ).fetchone()[0], "UNCERTAIN")
        return result

    def test_sigkill_after_stage_fsync_leaves_only_pending(self):
        self.assertEqual(self._sigkill("after_stage_fsync")["status"], "PENDING_ONLY")

    def test_sigkill_before_hardlink_leaves_only_pending(self):
        self.assertEqual(self._sigkill("before_link")["status"], "PENDING_ONLY")

    def test_sigkill_after_hardlink_detects_double_link(self):
        self.assertEqual(self._sigkill("after_link")["status"], "PUBLISHED_WITH_PENDING")


if __name__ == "__main__":
    unittest.main()
