#!/usr/bin/env python3
"""ODMM explicit local POSIX single-file lab CLI; NOT a NAS migrator.

Never overwrites targets; journals remain at the operator-chosen location.
No automatic replay or cleanup after an uncertain copy.
Author: Abdelhalim Talbi.
"""
import argparse
import json
import os
import sqlite3
import stat
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-Sources"))
from odmm_linux_lease_registry import initialize as init_leases, claim
from odmm_linux_datamover_intents import initialize as init_intents
from odmm_linux_lab_pipeline import run_lab_copy


def main(argv=None):
    parser = argparse.ArgumentParser(description="ODMM local POSIX lab file copy (not NAS-qualified)")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--ack-local-lab-only", action="store_true",
                        help="Confirm this is an isolated local POSIX lab, not a production NAS")
    args = parser.parse_args(argv)
    if not sys.platform.startswith("linux"):
        parser.error("Linux POSIX required")
    if not args.ack_local_lab_only:
        parser.error("Explicit --ack-local-lab-only is required")
    if not args.source.is_file() or args.source.is_symlink():
        parser.error("Source must be a regular non-symlink file")
    if not args.target.parent.is_dir() or args.target.exists() or args.target.is_symlink():
        parser.error("Target parent must exist and target must not exist")
    if args.journal.exists() or args.journal.is_symlink():
        parser.error("Journal must not exist; never reuse a journal automatically")
    if not args.journal.parent.is_dir() or args.journal.parent.is_symlink():
        parser.error("Journal parent must be a real existing directory")
    if args.journal.absolute() in (args.source.absolute(), args.target.absolute()):
        parser.error("Journal cannot overlap source or target")
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(args.journal, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("UNSAFE_JOURNAL")
        with sqlite3.connect(f"/proc/self/fd/{fd}", uri=False, isolation_level=None) as db:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            init_leases(db)
            init_intents(db)
            token = claim(db, "local-cli-task", "local-cli", 3600)
            result = run_lab_copy(
                db, intent_id="copy-" + uuid.uuid4().hex, task_id="local-cli-task",
                owner="local-cli", token=token, source=args.source, target=args.target)
            print(json.dumps({"state": result["state"],
                              "source": str(args.source), "target": str(args.target),
                              "journal": str(args.journal), "nas_migration_qualified": False},
                             sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"state": "FAILED_OR_UNCERTAIN", "reason": type(exc).__name__,
                          "journal": str(args.journal), "manual_review_required": True,
                          "nas_migration_qualified": False}), file=sys.stderr)
        return 1
    finally:
        os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
