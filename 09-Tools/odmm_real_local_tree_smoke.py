#!/usr/bin/env python3
"""Real multi-file local POSIX tree smoke; isolated, no NAS qualification.

Copies nested regular files through the ODMM journaled copy pipeline.
A deliberately interrupted file must remain UNCERTAIN and must not be replayed.
Author: Abdelhalim Talbi.
"""
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "02-Sources"))
from odmm_linux_lease_registry import initialize as init_leases, claim
from odmm_linux_datamover_intents import initialize as init_intents, quarantine_unfinished
from odmm_linux_lab_pipeline import run_lab_copy, LabPipelineError


def main():
    if not sys.platform.startswith("linux"):
        print("ERROR: Linux POSIX only", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="odmm-local-tree-") as tmp:
        root = Path(tmp)
        source, target = root / "source", root / "target"
        source.mkdir()
        target.mkdir()
        files = {
            "empty.bin": (b"", 0o600),
            "nested/utf8.txt": ("migration réelle — vérification".encode(), 0o640),
            "nested/deeper/random.bin": (os.urandom(131072), 0o644),
        }
        with sqlite3.connect(root / "journal.sqlite", isolation_level=None) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            init_leases(db)
            init_intents(db)
            for index, (relative, (data, mode)) in enumerate(files.items()):
                src, dst = source / relative, target / relative
                src.parent.mkdir(parents=True, exist_ok=True)
                dst.parent.mkdir(parents=True, exist_ok=True)
                src.write_bytes(data)
                src.chmod(mode)
                task = f"tree-task-{index}"
                token = claim(db, task, "smoke-worker", 120)
                result = run_lab_copy(
                    db, intent_id=f"tree-intent-{index}", task_id=task,
                    owner="smoke-worker", token=token, source=src, target=dst)
                assert result["state"] == "VERIFIED", "COPY_NOT_VERIFIED"
                assert hashlib.sha256(dst.read_bytes()).digest() == hashlib.sha256(data).digest(), "HASH_MISMATCH"
                assert dst.stat().st_mode & 0o777 == mode, "MODE_MISMATCH"
            src, dst = source / "interrupted.bin", target / "interrupted.bin"
            src.write_bytes(os.urandom(16384))
            token = claim(db, "interrupted-task", "smoke-worker", 120)
            try:
                run_lab_copy(db, intent_id="interrupted-intent",
                             task_id="interrupted-task", owner="smoke-worker",
                             token=token, source=src, target=dst,
                             fault_at="during_copy")
            except LabPipelineError as exc:
                assert str(exc) == "INJECTED_DURING_COPY", "UNEXPECTED_FAILURE"
            else:
                raise AssertionError("INTERRUPTION_NOT_TRIGGERED")
            quarantined = quarantine_unfinished(db)
            state = db.execute(
                "SELECT state FROM odmm_datamover_intents WHERE intent_id='interrupted-intent'"
            ).fetchone()[0]
            assert state == "UNCERTAIN" and quarantined == 1, "QUARANTINE_FAILED"
            assert dst.exists() and dst.stat().st_size < src.stat().st_size, "PARTIAL_TARGET_NOT_PRESERVED"
            verified = db.execute(
                "SELECT COUNT(*) FROM odmm_datamover_intents WHERE state='VERIFIED'"
            ).fetchone()[0]
            assert verified == len(files), "VERIFIED_COUNT_MISMATCH"
            print(json.dumps({
                "test": "real_local_posix_tree_and_interruption",
                "passed": True,
                "verified_files": verified,
                "interrupted_state": state,
                "partial_target_retained": True,
                "nas_migration_qualified": False,
                "nfs_smb_acl_qualified": False
            }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
