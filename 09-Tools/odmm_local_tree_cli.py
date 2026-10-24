#!/usr/bin/env python3
"""ODMM local POSIX tree-copy laboratory CLI.

Explicitly NOT NAS/NFS/SMB qualified. Refuses symlinks, special files, preexisting
destination, and source/target overlap. Never deletes or retries failed targets.
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


def inventory(root):
    files = []
    dirs = []
    for current, subdirs, filenames in os.walk(root, topdown=True, followlinks=False):
        for name in subdirs + filenames:
            path = Path(current) / name
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                dirs.append(path.relative_to(root))
            elif stat.S_ISREG(mode):
                files.append(path.relative_to(root))
            else:
                raise ValueError("UNSUPPORTED_SYMLINK_OR_SPECIAL_FILE: " + str(path))
    return sorted(dirs), sorted(files)


def main(argv=None):
    p = argparse.ArgumentParser(description="ODMM local POSIX tree-copy lab; NOT NAS qualified")
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--target", required=True, type=Path)
    p.add_argument("--ack-local-lab-only", action="store_true")
    args = p.parse_args(argv)
    if not sys.platform.startswith("linux"):
        p.error("Linux required")
    if not args.ack_local_lab_only:
        p.error("Explicit --ack-local-lab-only required")
    src, dst = args.source, args.target
    if src.is_symlink() or not src.is_dir() or dst.exists() or dst.is_symlink():
        p.error("Source must be a real directory; destination must not exist")
    if not dst.parent.is_dir() or dst.parent.is_symlink():
        p.error("Destination parent must be a real existing directory")
    resolved_src, resolved_dst = src.resolve(), dst.resolve()
    if resolved_src == resolved_dst or resolved_src in resolved_dst.parents or resolved_dst in resolved_src.parents:
        p.error("Source/destination overlap refused")
    try:
        dirs, files = inventory(src)
    except (ValueError, OSError) as exc:
        p.error(str(exc))
    created = False
    copied = 0
    try:
        dst.mkdir(mode=0o700)
        created = True
        for relative in dirs:
            (dst / relative).mkdir(mode=0o700)
        with sqlite3.connect(dst / ".odmm-local-journal.sqlite", isolation_level=None) as db:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            init_leases(db)
            init_intents(db)
            for index, relative in enumerate(files):
                task = f"tree-{index}"
                token = claim(db, task, "local-tree-worker", 3600)
                result = run_lab_copy(
                    db, intent_id="tree-" + uuid.uuid4().hex, task_id=task,
                    owner="local-tree-worker", token=token,
                    source=src / relative, target=dst / relative)
                if result["state"] != "VERIFIED":
                    raise RuntimeError("NOT_VERIFIED")
                copied += 1
        # Directory modes applied bottom-up after all children are written.
        for relative in reversed(dirs):
            os.chmod(dst / relative, stat.S_IMODE((src / relative).stat().st_mode))
        os.chmod(dst, stat.S_IMODE(src.stat().st_mode))
        print(json.dumps({"state": "VERIFIED", "files_copied": copied,
                          "directories_copied": len(dirs), "target": str(dst),
                          "journal": str(dst / ".odmm-local-journal.sqlite"),
                          "nas_migration_qualified": False}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"state": "FAILED_OR_UNCERTAIN",
                          "error": type(exc).__name__,
                          "files_completed": copied, "target_created": created,
                          "manual_review_required": True,
                          "nas_migration_qualified": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
