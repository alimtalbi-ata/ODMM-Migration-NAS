#!/usr/bin/env python3
"""Read-only local lab journal inspection; no automatic resume or repair.

Only accepts a regular single-link SQLite file. Uses SQLite mode=ro.
Author: Abdelhalim Talbi.
"""
import argparse
import json
import sqlite3
import stat
import sys
from pathlib import Path
from urllib.parse import quote


def main(argv=None):
    p = argparse.ArgumentParser(description="Inspect ODMM local POSIX lab intent states")
    p.add_argument("--journal", required=True, type=Path)
    args = p.parse_args(argv)
    path = args.journal
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("UNSAFE_JOURNAL")
        uri = "file:" + quote(str(path.resolve()), safe="/") + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as db:
            db.execute("PRAGMA query_only=ON")
            rows = db.execute(
                "SELECT intent_id,task_id,state FROM odmm_datamover_intents ORDER BY intent_id"
            ).fetchall()
        output = {
            "journal": str(path),
            "read_only": True,
            "nas_migration_qualified": False,
            "authorizes_resume": False,
            "intents": [{"intent_id": i, "task_id": t, "state": s}
                        for i, t, s in rows],
        }
        print(json.dumps(output, sort_keys=True))
        return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(json.dumps({"error": type(exc).__name__, "read_only": True,
                          "authorizes_resume": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
