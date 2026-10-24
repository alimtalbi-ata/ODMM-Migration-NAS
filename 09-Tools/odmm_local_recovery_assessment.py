#!/usr/bin/env python3
"""Read-only recovery assessment combining local POSIX tree and SQLite journal.

Never authorizes automatic replay; never modifies journal or destination.
Older lab journals may lack task-to-path mappings. No automatic replay.
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
    with sqlite3.connect(uri, uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        available = db.execute("""SELECT count(*) FROM sqlite_master
            WHERE type='table' AND name='odmm_tree_task_paths'""").fetchone()[0]
        mapping_rows = db.execute("""SELECT task_id,relative_path,source_dev,source_ino,
            source_size,source_mtime_ns,source_ctime_ns FROM odmm_tree_task_paths""").fetchall() if available else []
    mapping = {row[0]: row[1:] for row in mapping_rows}
    task_ids = {task_id for _, task_id, _ in rows}
    orphan_mappings = sorted(set(mapping) - task_ids)
    unresolved = []
    for intent_id, task_id, state in rows:
        if state not in ("PREPARED", "IN_FLIGHT", "UNCERTAIN"):
            continue
        entry = {"intent_id": intent_id, "task_id": task_id, "state": state}
        mapped = mapping.get(task_id)
        if mapped:
            relative, dev, ino, size, mtime, ctime = mapped
            entry["relative_path"] = relative
            # A source may change after interruption; never silently reuse it.
            path = source / relative
            try:
                parts = Path(relative).parts
                if (not parts or Path(relative).is_absolute() or
                        any(part in ("..", ".") for part in parts) or
                        any((source.joinpath(*parts[:index])).is_symlink()
                            for index in range(1, len(parts) + 1))):
                    raise ValueError("UNSAFE_MAPPED_PATH")
                info = path.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("UNSAFE_MAPPED_FILE")
                entry["source_identity_matches"] = (
                    (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                     info.st_ctime_ns) == (dev, ino, size, mtime, ctime))
            except (OSError, ValueError):
                entry["source_identity_matches"] = False
        else:
            entry["mapping_missing"] = True
        unresolved.append(entry)
    return {"status": "MANUAL_REVIEW_REQUIRED" if unresolved or findings or orphan_mappings else "CURRENT_FILES_MATCH",
            "tree_counts": counts, "tree_findings": findings,
            "unresolved_intents": unresolved, "total_intents": len(rows),
            "orphan_task_mappings": orphan_mappings,
            "mapping_limit": "TASK_TO_PATH_AVAILABLE" if available else "NO_DURABLE_TASK_TO_PATH_MAPPING",
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
