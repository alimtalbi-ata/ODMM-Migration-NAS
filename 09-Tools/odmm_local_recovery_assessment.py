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


def assess(source, target, journal, *, inspect_posix_metadata=False):
    info = journal.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("UNSAFE_JOURNAL")
    uri = "file:" + quote(str(journal.resolve()), safe="/") + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("JOURNAL_INTEGRITY_FAILED")
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
    duplicate_mapping_tasks = sorted(
        task_id for task_id in {row[0] for row in mapping_rows}
        if sum(row[0] == task_id for row in mapping_rows) > 1)
    path_occurrences = {}
    for row in mapping_rows:
        path_occurrences[row[1]] = path_occurrences.get(row[1], 0) + 1
    duplicate_mapped_paths = sorted(
        path for path, count in path_occurrences.items() if count > 1)
    task_ids = {task_id for _, task_id, _ in rows}
    task_occurrences = {}
    for _, task_id, _ in rows:
        task_occurrences[task_id] = task_occurrences.get(task_id, 0) + 1
    duplicate_intent_tasks = sorted(task_id for task_id, count in task_occurrences.items()
                                    if count > 1)
    orphan_mappings = sorted(set(mapping) - task_ids)
    unresolved = []
    for intent_id, task_id, state in rows:
        if state not in ("PREPARED", "IN_FLIGHT", "UNCERTAIN", "VERIFIED"):
            unresolved.append({"intent_id": intent_id, "task_id": task_id,
                               "state": state, "reason": "UNKNOWN_INTENT_STATE"})
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
        if state != "VERIFIED" or entry.get("source_identity_matches") is False or entry.get("mapping_missing"):
            unresolved.append(entry)
    metadata_findings = []
    if inspect_posix_metadata:
        # Optional advisory: do not silently redefine older local-copy guarantees.
        import importlib.util
        source_modules = str(Path(__file__).resolve().parents[1] / "02-Sources")
        if source_modules not in sys.path:
            sys.path.insert(0, source_modules)
        module_path = Path(__file__).resolve().parents[1] / "02-Sources" / "odmm_linux_lab_metadata.py"
        spec = importlib.util.spec_from_file_location("odmm_linux_lab_metadata", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for entry in unresolved:
            relative = entry.get("relative_path")
            if relative and entry.get("source_identity_matches") is True:
                outcome = module.inspect_metadata(source / relative, target / relative)
                if outcome["status"] != "LOCAL_METADATA_MATCH":
                    metadata_findings.append({"task_id": entry["task_id"],
                                              "relative_path": relative,
                                              "result": outcome})
    missing_evidence = not rows or not available or not mapping_rows
    return {"status": "MANUAL_REVIEW_REQUIRED" if missing_evidence or unresolved or findings or orphan_mappings or duplicate_intent_tasks or duplicate_mapping_tasks or duplicate_mapped_paths or metadata_findings else "CURRENT_FILES_MATCH",
            "tree_counts": counts, "tree_findings": findings,
            "posix_metadata_findings": metadata_findings,
            "posix_metadata_inspection_enabled": inspect_posix_metadata,
            "unresolved_intents": unresolved, "total_intents": len(rows),
            "missing_recovery_evidence": missing_evidence,
            "orphan_task_mappings": orphan_mappings,
            "duplicate_intent_tasks": duplicate_intent_tasks,
            "duplicate_mapping_tasks": duplicate_mapping_tasks,
            "duplicate_mapped_paths": duplicate_mapped_paths,
            "mapping_limit": "TASK_TO_PATH_AVAILABLE" if available else "NO_DURABLE_TASK_TO_PATH_MAPPING",
            "read_only": True, "authorizes_resume": False,
            "nas_migration_qualified": False}


def main(argv=None):
    p = argparse.ArgumentParser(description="Read-only local recovery assessment")
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--target", required=True, type=Path)
    p.add_argument("--journal", required=True, type=Path)
    p.add_argument("--inspect-posix-metadata", action="store_true",
                   help="Advisory read-only metadata inspection of unresolved mapped tasks")
    args = p.parse_args(argv)
    if not sys.platform.startswith("linux"):
        p.error("Linux required")
    try:
        report = assess(args.source, args.target, args.journal,
                        inspect_posix_metadata=args.inspect_posix_metadata)
        print(json.dumps(report, sort_keys=True))
        return 2 if report["status"] == "MANUAL_REVIEW_REQUIRED" else 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(json.dumps({"status": "ASSESSMENT_FAILED", "error": type(exc).__name__,
                          "read_only": True, "authorizes_resume": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
