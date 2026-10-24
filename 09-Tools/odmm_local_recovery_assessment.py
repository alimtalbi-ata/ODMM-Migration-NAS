#!/usr/bin/env python3
"""Read-only recovery assessment combining local POSIX tree and SQLite journal.

Never authorizes automatic replay; never modifies journal or destination.
The task-to-path mapping is not persisted in this lab journal, so findings
cannot be assigned reliably to individual intents.
"""
import argparse
import json
import sqlite3
import stat
import sys
from pathlib import Path
from urllib.parse import quote
from odmm_local_tree_recovery_triage import inspect


def assess(source, target, journal):
    info = journal.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("UNSAFE_JOURNAL")
    uri = "file:" + quote(str(journal.resolve()), safe="/") + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        rows = db.execute(
            "SELECT intent_id,task_id,state FROM odmm_datamover_intents ORDER BY intent_id"
        ).fetchall()
    counts, findings = inspect(source, target)
    unresolved = [{"intent_id": i, "task_id": t, "state": s}
                  for i, t, s in rows if s in ("PREPARED", "IN_FLIGHT", "UNCERTAIN")]
    return {"status": "MANUAL_REVIEW_REQUIRED" if unresolved or findings else "CURRENT_FILES_MATCH",
            "tree_counts": counts, "tree_findings": findings,
            "unresolved_intents": unresolved, "total_intents": len(rows),
            "mapping_limit": "NO_DURABLE_TASK_TO_PATH_MAPPING",
            "read_only": True, "authorizes_resume": False,
            "nas_migration_qualified": False}


def main(argv=None):
    p = argparse.ArgumentParser(description="Read-only local recovery assessment")
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--target", required=True, type=Path)
    p.add_argument("--journal", required=True, type=Path)
    args = p.parse_args(argv)
    if not sys.platform.startswith("linux"):
        p.error("Linux required")
    try:
        report = assess(args.source, args.target, args.journal)
        print(json.dumps(report, sort_keys=True))
        return 2 if report["status"] == "MANUAL_REVIEW_REQUIRED" else 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(json.dumps({"status": "ASSESSMENT_FAILED", "error": type(exc).__name__,
                          "read_only": True, "authorizes_resume": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
