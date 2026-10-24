"""Acceptance for combined read-only SQLite and tree recovery assessment."""
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "odmm_local_recovery_assessment.py"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux only")
class CombinedRecoveryTests(unittest.TestCase):
    def test_duplicate_mapped_path_blocks_clean_assessment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            src.mkdir()
            dst.mkdir()
            (src / "data").write_bytes(b"same")
            (dst / "data").write_bytes(b"same")
            info = (src / "data").stat()
            with sqlite3.connect(journal) as db:
                db.execute("CREATE TABLE odmm_datamover_intents (intent_id TEXT, task_id TEXT, state TEXT)")
                db.executemany("INSERT INTO odmm_datamover_intents VALUES (?,?,?)",
                               [("i1", "tree-0", "VERIFIED"), ("i2", "tree-1", "VERIFIED")])
                db.execute("""CREATE TABLE odmm_tree_task_paths
                    (task_id TEXT,relative_path TEXT,source_dev INTEGER,source_ino INTEGER,
                     source_size INTEGER,source_mtime_ns INTEGER,source_ctime_ns INTEGER)""")
                for task in ("tree-0", "tree-1"):
                    db.execute("INSERT INTO odmm_tree_task_paths VALUES (?,?,?,?,?,?,?)",
                               (task, "data", info.st_dev, info.st_ino, info.st_size,
                                info.st_mtime_ns, info.st_ctime_ns))
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["duplicate_mapped_paths"], ["data"])
            self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertFalse(report["authorizes_resume"])

    def test_corrupt_sqlite_journal_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            src.mkdir()
            dst.mkdir()
            journal.write_bytes(b"not a SQLite database" * 10)
            before = journal.read_bytes()
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stderr)["status"], "ASSESSMENT_FAILED")
            self.assertEqual(journal.read_bytes(), before)

    def test_orphan_mapping_blocks_clean_assessment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            src.mkdir()
            dst.mkdir()
            with sqlite3.connect(journal) as db:
                db.execute("CREATE TABLE odmm_datamover_intents (intent_id TEXT, task_id TEXT, state TEXT)")
                db.execute("""CREATE TABLE odmm_tree_task_paths
                    (task_id TEXT,relative_path TEXT,source_dev INTEGER,source_ino INTEGER,
                     source_size INTEGER,source_mtime_ns INTEGER,source_ctime_ns INTEGER)""")
                db.execute("INSERT INTO odmm_tree_task_paths VALUES (?,?,?,?,?,?,?)",
                           ("orphan-task", "lost", 0, 0, 0, 0, 0))
            before = journal.read_bytes()
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["orphan_task_mappings"], ["orphan-task"])
            self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertFalse(report["authorizes_resume"])
            self.assertEqual(journal.read_bytes(), before)

    def test_mapped_symlink_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            outside = root / "outside"
            src.mkdir()
            dst.mkdir()
            outside.mkdir()
            (outside / "data").write_bytes(b"secret")
            (src / "redirect").symlink_to(outside, target_is_directory=True)
            with sqlite3.connect(journal) as db:
                db.execute("CREATE TABLE odmm_datamover_intents (intent_id TEXT, task_id TEXT, state TEXT)")
                db.execute("INSERT INTO odmm_datamover_intents VALUES ('i1','tree-0','IN_FLIGHT')")
                db.execute("""CREATE TABLE odmm_tree_task_paths
                    (task_id TEXT,relative_path TEXT,source_dev INTEGER,source_ino INTEGER,
                     source_size INTEGER,source_mtime_ns INTEGER,source_ctime_ns INTEGER)""")
                db.execute("INSERT INTO odmm_tree_task_paths VALUES (?,?,?,?,?,?,?)",
                           ("tree-0", "redirect/data", 0, 0, 0, 0, 0))
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertFalse(report["unresolved_intents"][0]["source_identity_matches"])
            self.assertFalse(report["authorizes_resume"])
            self.assertEqual((outside / "data").read_bytes(), b"secret")

    def test_mapped_intent_reports_changed_source_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            src.mkdir()
            dst.mkdir()
            file = src / "data"
            file.write_bytes(b"initial")
            info = file.stat()
            with sqlite3.connect(journal) as db:
                db.execute("CREATE TABLE odmm_datamover_intents (intent_id TEXT, task_id TEXT, state TEXT)")
                db.execute("INSERT INTO odmm_datamover_intents VALUES ('i1','tree-0','IN_FLIGHT')")
                db.execute("""CREATE TABLE odmm_tree_task_paths
                    (task_id TEXT,relative_path TEXT,source_dev INTEGER,source_ino INTEGER,
                     source_size INTEGER,source_mtime_ns INTEGER,source_ctime_ns INTEGER)""")
                db.execute("INSERT INTO odmm_tree_task_paths VALUES (?,?,?,?,?,?,?)",
                           ("tree-0", "data", info.st_dev, info.st_ino, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns))
            file.write_bytes(b"changed")
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["mapping_limit"], "TASK_TO_PATH_AVAILABLE")
            self.assertEqual(report["unresolved_intents"][0]["relative_path"], "data")
            self.assertFalse(report["unresolved_intents"][0]["source_identity_matches"])
            self.assertFalse(report["authorizes_resume"])

    def test_duplicate_intents_for_one_task_require_manual_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            src.mkdir()
            dst.mkdir()
            with sqlite3.connect(journal) as db:
                db.execute("CREATE TABLE odmm_datamover_intents (intent_id TEXT, task_id TEXT, state TEXT)")
                db.execute("INSERT INTO odmm_datamover_intents VALUES ('i1','tree-0','VERIFIED')")
                db.execute("INSERT INTO odmm_datamover_intents VALUES ('i2','tree-0','VERIFIED')")
            before = journal.read_bytes()
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["duplicate_intent_tasks"], ["tree-0"])
            self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertFalse(report["authorizes_resume"])
            self.assertEqual(journal.read_bytes(), before)

    def test_verified_intent_with_changed_source_requires_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            src.mkdir()
            dst.mkdir()
            file = src / "data"
            file.write_bytes(b"before")
            (dst / "data").write_bytes(b"after!")
            info = file.stat()
            with sqlite3.connect(journal) as db:
                db.execute("CREATE TABLE odmm_datamover_intents (intent_id TEXT, task_id TEXT, state TEXT)")
                db.execute("INSERT INTO odmm_datamover_intents VALUES ('verified-1','tree-0','VERIFIED')")
                db.execute("""CREATE TABLE odmm_tree_task_paths
                    (task_id TEXT,relative_path TEXT,source_dev INTEGER,source_ino INTEGER,
                     source_size INTEGER,source_mtime_ns INTEGER,source_ctime_ns INTEGER)""")
                db.execute("INSERT INTO odmm_tree_task_paths VALUES (?,?,?,?,?,?,?)",
                           ("tree-0", "data", info.st_dev, info.st_ino, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns))
            file.write_bytes(b"after!")
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertEqual(report["unresolved_intents"][0]["state"], "VERIFIED")
            self.assertFalse(report["unresolved_intents"][0]["source_identity_matches"])

    def test_matching_files_without_task_evidence_cannot_be_declared_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            src.mkdir()
            dst.mkdir()
            (src / "data").write_bytes(b"same")
            (dst / "data").write_bytes(b"same")
            with sqlite3.connect(journal) as db:
                db.execute("CREATE TABLE odmm_datamover_intents (intent_id TEXT, task_id TEXT, state TEXT)")
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["tree_counts"]["verified_files"], 1)
            self.assertTrue(report["missing_recovery_evidence"])
            self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertFalse(report["authorizes_resume"])

    def test_unresolved_intent_and_missing_file_are_both_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            src.mkdir()
            dst.mkdir()
            (src / "data").write_bytes(b"important")
            with sqlite3.connect(journal) as db:
                db.execute("CREATE TABLE odmm_datamover_intents (intent_id TEXT, task_id TEXT, state TEXT)")
                db.execute("INSERT INTO odmm_datamover_intents VALUES ('i1','task1','IN_FLIGHT')")
            before = journal.read_bytes()
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertEqual(report["tree_counts"]["missing_files"], 1)
            self.assertEqual(report["unresolved_intents"][0]["state"], "IN_FLIGHT")
            self.assertEqual(report["mapping_limit"], "NO_DURABLE_TASK_TO_PATH_MAPPING")
            self.assertFalse(report["authorizes_resume"])
            self.assertEqual(journal.read_bytes(), before)
            self.assertFalse((dst / "data").exists())

    def test_unknown_intent_state_fails_closed_even_with_matching_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            src.mkdir()
            dst.mkdir()
            (src / "data").write_bytes(b"same")
            (dst / "data").write_bytes(b"same")
            info = (src / "data").stat()
            with sqlite3.connect(journal) as db:
                db.execute("CREATE TABLE odmm_datamover_intents (intent_id TEXT, task_id TEXT, state TEXT)")
                db.execute("INSERT INTO odmm_datamover_intents VALUES ('i1','tree-0','FUTURE_STATE')")
                db.execute("""CREATE TABLE odmm_tree_task_paths
                    (task_id TEXT,relative_path TEXT,source_dev INTEGER,source_ino INTEGER,
                     source_size INTEGER,source_mtime_ns INTEGER,source_ctime_ns INTEGER)""")
                db.execute("INSERT INTO odmm_tree_task_paths VALUES (?,?,?,?,?,?,?)",
                           ("tree-0", "data", info.st_dev, info.st_ino, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns))
            before = journal.read_bytes()
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "MANUAL_REVIEW_REQUIRED")
            self.assertEqual(report["unresolved_intents"][0]["reason"], "UNKNOWN_INTENT_STATE")
            self.assertFalse(report["authorizes_resume"])
            self.assertEqual(journal.read_bytes(), before)
            self.assertEqual((dst / "data").read_bytes(), b"same")

    def test_opt_in_metadata_mismatch_reports_read_only_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, dst, journal = root / "source", root / "target", root / "journal.sqlite"
            src.mkdir()
            dst.mkdir()
            (src / "data").write_bytes(b"same")
            (dst / "data").write_bytes(b"same")
            (src / "data").chmod(0o600)
            (dst / "data").chmod(0o644)
            info = (src / "data").stat()
            with sqlite3.connect(journal) as db:
                db.execute("CREATE TABLE odmm_datamover_intents (intent_id TEXT, task_id TEXT, state TEXT)")
                db.execute("INSERT INTO odmm_datamover_intents VALUES ('i1','tree-0','UNCERTAIN')")
                db.execute("""CREATE TABLE odmm_tree_task_paths
                    (task_id TEXT,relative_path TEXT,source_dev INTEGER,source_ino INTEGER,
                     source_size INTEGER,source_mtime_ns INTEGER,source_ctime_ns INTEGER)""")
                db.execute("INSERT INTO odmm_tree_task_paths VALUES (?,?,?,?,?,?,?)",
                           ("tree-0", "data", info.st_dev, info.st_ino, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns))
            before = journal.read_bytes()
            result = subprocess.run([sys.executable, str(TOOL), "--source", str(src),
                                     "--target", str(dst), "--journal", str(journal),
                                     "--inspect-posix-metadata"],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report["posix_metadata_inspection_enabled"])
            self.assertEqual(report["posix_metadata_findings"][0]["task_id"], "tree-0")
            self.assertIn("mode", report["posix_metadata_findings"][0]["result"]["differences"])
            self.assertFalse(report["authorizes_resume"])
            self.assertEqual(journal.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
