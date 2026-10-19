"""Read-only SQLite durability contract checker.

Checks database integrity and durability configuration without mutating the
registry or authorizing migration/cutover. Author: Abdelhalim Talbi.
"""
import argparse
from contextlib import closing
import json
import sqlite3
from pathlib import Path


def inspect_registry(path):
    db = Path(path)
    if not db.is_file():
        raise ValueError("REGISTRY_NOT_FOUND")
    # Open read-only: never initialize a missing registry.
    with closing(sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True, timeout=3)) as conn:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        journal = conn.execute("PRAGMA journal_mode").fetchone()[0]
        synchronous = conn.execute("PRAGMA synchronous").fetchone()[0]
        quick = conn.execute("PRAGMA quick_check").fetchone()[0]
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        pending_intents = (conn.execute("SELECT COUNT(*) FROM intents").fetchone()[0]
                           if "intents" in tables else None)
        verified_files = (conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
                          if "files" in tables else None)
    return {
        "schema": "odmm.sqlite.registry.audit.v1",
        "registry": db.name,
        "integrity_check": integrity,
        "quick_check": quick,
        "journal_mode": journal,
        "synchronous": synchronous,
        "synchronous_scope": "audit_connection_only_not_writer_durability_proof",
        "pending_intents": pending_intents,
        "verified_files": verified_files,
        "reconciliation_required": bool(pending_intents),
        "native_schema_detected": "files" in tables and "intents" in tables,
        "passed": integrity == "ok" and quick == "ok" and journal.lower() == "wal",
        "scope": "read-only local SQLite checks; writer synchronous setting not provable; no NAS ACL or cutover qualification",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("database")
    parser.add_argument("--output")
    args = parser.parse_args()
    result = inspect_registry(args.database)
    payload = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
