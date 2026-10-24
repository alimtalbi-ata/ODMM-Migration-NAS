#!/usr/bin/env python3
"""Read-only recovery triage for a failed local POSIX tree copy.

Compares the current source and destination without authorizing resume.
Not a consistent snapshot; not NFS/SMB qualified.
"""
import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path


def digest(path, inventoried):
    """Reject inode replacement or metadata drift around hashing.

    This is a best-effort POSIX race fence, not an atomic filesystem snapshot.
    """
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                info.st_ctime_ns, info.st_mode, info.st_nlink)

    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                identity(before) != identity(inventoried)):
            raise RuntimeError("FILE_CHANGED_BEFORE_HASH")
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
        after = os.fstat(fd)
        if identity(before) != identity(after) or identity(after) != identity(path.lstat()):
            raise RuntimeError("FILE_CHANGED_DURING_HASH")
        return h.hexdigest()
    finally:
        os.close(fd)


def inspect(source, target):
    findings = []
    counts = {"verified_files": 0, "missing_files": 0,
              "mismatched_files": 0, "unexpected_entries": 0}
    if source.is_symlink() or target.is_symlink() or not source.is_dir() or not target.is_dir():
        return counts, [{"code": "INVALID_ROOT", "path": str(target)}]

    def walk_error(exc):
        raise OSError("TREE_TRAVERSAL_FAILED: " + str(exc)) from exc

    source_entries = {}
    target_entries = {}
    for root, mapping in ((source, source_entries), (target, target_entries)):
        for current, directories, filenames in os.walk(root, followlinks=False, onerror=walk_error):
            for name in directories + filenames:
                path = Path(current) / name
                relative = str(path.relative_to(root))
                info = path.lstat()
                mapping[relative] = (path, info)
    for relative, (src, info) in sorted(source_entries.items()):
        if not stat.S_ISREG(info.st_mode):
            if not stat.S_ISDIR(info.st_mode):
                findings.append({"code": "UNSUPPORTED_SOURCE_ENTRY", "path": relative})
            elif relative not in target_entries or not stat.S_ISDIR(target_entries[relative][1].st_mode):
                findings.append({"code": "MISSING_DIRECTORY", "path": relative})
            elif stat.S_IMODE(info.st_mode) != stat.S_IMODE(target_entries[relative][1].st_mode):
                findings.append({"code": "DIRECTORY_MODE_MISMATCH", "path": relative})
            continue
        dest = target_entries.get(relative)
        if dest is None:
            counts["missing_files"] += 1
            findings.append({"code": "MISSING_FILE", "path": relative})
        elif not stat.S_ISREG(dest[1].st_mode) or dest[1].st_nlink != 1:
            counts["mismatched_files"] += 1
            findings.append({"code": "UNSAFE_TARGET_FILE", "path": relative})
        elif (info.st_size != dest[1].st_size or
              stat.S_IMODE(info.st_mode) != stat.S_IMODE(dest[1].st_mode) or
              digest(src, info) != digest(dest[0], dest[1])):
            counts["mismatched_files"] += 1
            findings.append({"code": "FILE_MISMATCH", "path": relative})
        else:
            counts["verified_files"] += 1
    for relative in sorted(set(target_entries) - set(source_entries)):
        if relative == ".odmm-local-journal.sqlite":
            continue
        counts["unexpected_entries"] += 1
        findings.append({"code": "UNEXPECTED_TARGET_ENTRY", "path": relative})
    return counts, findings


def main(argv=None):
    p = argparse.ArgumentParser(description="Read-only local tree recovery triage; no automatic resume")
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--target", required=True, type=Path)
    args = p.parse_args(argv)
    if not sys.platform.startswith("linux"):
        p.error("Linux required")
    try:
        counts, findings = inspect(args.source, args.target)
        report = {"status": "MANUAL_REVIEW_REQUIRED" if findings else "CURRENT_FILES_MATCH",
                  "counts": counts, "findings": findings,
                  "read_only": True, "authorizes_resume": False,
                  "nas_migration_qualified": False}
        print(json.dumps(report, sort_keys=True))
        return 2 if findings else 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"status": "INSPECTION_FAILED", "error": type(exc).__name__,
                          "read_only": True, "authorizes_resume": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
