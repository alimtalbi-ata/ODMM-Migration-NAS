"""Subprocess SIGKILL crash test for Linux lab journal and exclusive-create target.

Tests process termination, NOT host power loss or remote NAS durability.
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
from odmm_linux_datamover_intents import unresolved, quarantine_unfinished

class ProcessCrashTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux only")
    def test_sigkill_after_durable_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db_path = root / "registry.db"
            source = root / "source"
            target = root / "target"
            source.write_bytes(b"source-data" * 4096)
            child = textwrap.dedent("""
                import os, sqlite3, sys
                from odmm_linux_lease_registry import initialize as init_lease, claim
                from odmm_linux_datamover_intents import initialize as init_intents
                from odmm_linux_lab_pipeline import run_lab_copy
                db = sqlite3.connect(sys.argv[1], isolation_level=None)
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("PRAGMA synchronous=FULL")
                init_lease(db)
                init_intents(db)
                token = claim(db, "task", "worker", 120)
                try:
                    run_lab_copy(db, intent_id="crash", task_id="task", owner="worker",
                                 token=token, source=sys.argv[2], target=sys.argv[3],
                                 fault_at="after_intent")
                except Exception:
                    print("INTENT_DURABLE", flush=True)
                    os.kill(os.getpid(), 9)
                """)
            proc = subprocess.run(
                [sys.executable, "-c", child, str(db_path), str(source), str(target)],
                cwd=root, env={**os.environ, "PYTHONPATH": str(ROOT / "02-Sources")},
                capture_output=True, text=True, timeout=20, check=False)
            self.assertEqual(proc.returncode, -signal.SIGKILL, proc.stderr)
            self.assertIn("INTENT_DURABLE", proc.stdout)
            self.assertFalse(target.exists())
            db = sqlite3.connect(db_path, isolation_level=None)
            try:
                self.assertEqual(unresolved(db)[0][-1], "IN_FLIGHT")
                self.assertEqual(quarantine_unfinished(db), 1)
                self.assertEqual(unresolved(db)[0][-1], "UNCERTAIN")
            finally:
                db.close()

if __name__ == "__main__":
    unittest.main()
