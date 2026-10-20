#!/usr/bin/env python3
"""Non-destructive Linux infrastructure/portable preflight; stdlib only.

Author: Abdelhalim Talbi. This check never mounts, copies or modifies NAS data.
"""
import argparse
import json
import os
import platform
import shutil
import socket
import sys
from pathlib import Path

def inspect(root, edition):
    root = Path(root).resolve()
    sources = root / "02-Sources"
    checks = {
        "linux_host": sys.platform.startswith("linux"),
        "python_3_10_plus": sys.version_info >= (3, 10),
        "sources_available": sources.is_dir(),
        "compact_entrypoint": (sources / "odmm_linux_compact_v22811.py").is_file(),
        "full_entrypoint": (root / "03-Build-Installation/RUN-LINUX-FULL.sh").is_file(),
        "hostname_available": bool(socket.gethostname()),
        "disk_free_1g": shutil.disk_usage(root).free >= 1024**3,
    }
    if edition == "full":
        checks["sqlite_available"] = _sqlite_available()
        checks["flock_available"] = _flock_available()
    result = {
        "schema_version": 1, "edition": edition, "hostname": socket.gethostname(),
        "os": platform.system(), "architecture": platform.machine(),
        "checks": checks, "passed": all(checks.values()),
        "nas_migration_qualified": False,
        "note": "Preflight only; no NAS migration, SMB/ACL or HA validation performed",
    }
    return result

def _sqlite_available():
    try:
        import sqlite3
        with sqlite3.connect(":memory:") as db:
            return db.execute("pragma integrity_check").fetchone()[0] == "ok"
    except (ImportError, Exception):
        return False

def _flock_available():
    try:
        import fcntl
        return hasattr(fcntl, "flock")
    except ImportError:
        return False

def main(argv=None):
    parser = argparse.ArgumentParser(description="ODMM Linux non-destructive deployment preflight")
    parser.add_argument("--edition", choices=("compact", "full"), required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        result = inspect(args.root, args.edition)
    except OSError:
        print(json.dumps({"passed": False, "error": "PREFLIGHT_IO_FAILURE"}))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
