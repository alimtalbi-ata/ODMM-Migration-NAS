"""Isolated Linux POSIX read-only crash inventory tests (no NAS).

Author: Abdelhalim Talbi.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02-Sources"))
import odmm_linux_lab_rotation_review as review
from odmm_linux_lab_anchor_rotation import _receipt_name


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux POSIX lab only")
class RotationOrphanReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.final = self.root / _receipt_name("copy", "new")
        self.pending = self.root / (self.final.name + ".pending-" + "a" * 32)

    def scan(self):
        return review.review_rotation_orphans(self.root, "copy", "new")

    def put(self, path, content=b"laboratory-only"):
        path.write_bytes(content)
        path.chmod(0o600)

    def test_absent_is_read_only_and_not_authorized(self):
        r = self.scan()
        self.assertTrue(r["inventory_complete"])
        self.assertEqual(r["status"], "ABSENT")
        self.assertEqual(r["manifest"]["files"], [])
        self.assertFalse(r["authorizes_resume"])
        self.assertFalse(r["authorizes_cleanup"])

    def test_pending_only_hashes_bytes_without_removing_file(self):
        self.put(self.pending)
        before = self.pending.read_bytes()
        r = self.scan()
        self.assertEqual(r["status"], "PENDING_ONLY")
        self.assertTrue(r["inventory_complete"])
        self.assertEqual(len(r["manifest"]["files"]), 1)
        self.assertEqual(self.pending.read_bytes(), before)

    def test_hardlinked_published_pending_remains_quarantined(self):
        self.put(self.pending)
        os.link(self.pending, self.final)
        r = self.scan()
        self.assertEqual(r["status"], "PUBLISHED_WITH_PENDING")
        self.assertTrue(r["inventory_complete"])
        self.assertEqual(r["manifest"]["files"][0]["sha256"],
                         r["manifest"]["files"][1]["sha256"])
        self.assertTrue(self.pending.exists() and self.final.exists())
        self.assertFalse(r["authorizes_resume"])

    def test_unrelated_pending_and_final_both_preserved(self):
        self.put(self.final, b"final")
        self.put(self.pending, b"pending")
        r = self.scan()
        self.assertEqual(r["status"], "UNRELATED_PENDING")
        self.assertTrue(r["inventory_complete"])
        self.assertEqual(len(r["manifest"]["files"]), 2)
        self.assertNotEqual(r["manifest"]["files"][0]["sha256"],
                            r["manifest"]["files"][1]["sha256"])

    def test_clean_final_is_not_cryptographic_authentication(self):
        self.put(self.final)
        r = self.scan()
        self.assertEqual(r["status"], "FINAL_PRESENT_UNVERIFIED")
        self.assertTrue(r["inventory_complete"])
        self.assertFalse(r["authorizes_resume"])

    def test_symlink_is_rejected_without_following(self):
        victim = self.root / "victim"
        self.put(victim, b"do-not-read")
        self.pending.symlink_to(victim)
        r = self.scan()
        self.assertFalse(r["inventory_complete"])
        self.assertNotIn("manifest", r)
        self.assertEqual(victim.read_bytes(), b"do-not-read")

    def test_permission_weakening_is_rejected(self):
        self.put(self.pending)
        self.pending.chmod(0o644)
        self.assertFalse(self.scan()["inventory_complete"])

    def test_same_size_in_place_change_after_digest_fails_closed(self):
        self.put(self.pending, b"aaaa")
        original = review._digest_leaf
        def mutate(*args):
            result = original(*args)
            self.pending.write_bytes(b"bbbb")
            return result
        with patch.object(review, "_digest_leaf", side_effect=mutate):
            self.assertFalse(self.scan()["inventory_complete"])

    def test_oversized_receipt_fails_closed(self):
        self.put(self.pending, b"x" * (review._MAX_RECEIPT + 1))
        self.assertFalse(self.scan()["inventory_complete"])


if __name__ == "__main__":
    unittest.main()
