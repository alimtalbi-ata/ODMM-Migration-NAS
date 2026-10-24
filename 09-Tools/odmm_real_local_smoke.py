#!/usr/bin/env python3
"""Executable ODMM local POSIX copy smoke, not an NFS/SMB qualification.

Runs an actual file copy with the native journal/lease pipeline inside a
disposable temporary directory. Never accepts a user-supplied NAS path.
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
from odmm_linux_datamover_intents import initialize as init_intents
from odmm_linux_lab_pipeline import run_lab_copy


def main():
    if not sys.platform.startswith("linux"):
        print("ERROR: Linux POSIX only", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="odmm-real-local-smoke-") as tmp:
        root = Path(tmp)
        (root / "source").mkdir()
        (root / "target").mkdir()
        src, dst = root / "source" / "payload.bin", root / "target" / "payload.bin"
        payload = os.urandom(262144) + b"ODMM-real-local-copy-smoke"
        src.write_bytes(payload)
        src.chmod(0o640)
        with sqlite3.connect(root / "journal.sqlite", isolation_level=None) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            init_leases(db)
            init_intents(db)
            token = claim(db, "smoke-task", "smoke-worker", 120)
            result = run_lab_copy(db, intent_id="smoke-intent",
                                  task_id="smoke-task", owner="smoke-worker",
                                  token=token, source=src, target=dst)
            state = db.execute(
                "SELECT state FROM odmm_datamover_intents WHERE intent_id=?",
                ("smoke-intent",)).fetchone()[0]
            actual = dst.read_bytes()
            success = (result["state"] == state == "VERIFIED"
                       and actual == payload
                       and (dst.stat().st_mode & 0o777) == 0o640
                       and result["production_nas_qualified"] is False)
            print(json.dumps({
                "test": "real_local_posix_copy",
                "passed": success,
                "bytes_copied": len(actual),
                "sha256": hashlib.sha256(actual).hexdigest(),
                "journal_state": state,
                "posix_mode": oct(dst.stat().st_mode & 0o777),
                "nas_migration_qualified": False,
                "nfs_smb_acl_qualified": False,
                "temporary_data_removed_on_exit": True
            }, sort_keys=True))
            return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
