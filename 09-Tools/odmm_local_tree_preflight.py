#!/usr/bin/env python3
"""Read-only local POSIX migration preflight; NOT NAS/NFS/SMB qualified."""
import argparse
import json
import os
import stat
import sys
from pathlib import Path


def inspect(source, target):
    findings = []
    count = 0
    total_bytes = 0

    def issue(code, path):
        findings.append({"code": code, "path": str(path)})

    if source.is_symlink() or not source.is_dir():
        issue("INVALID_SOURCE", source)
        return count, total_bytes, findings
    if target.exists() or target.is_symlink():
        issue("TARGET_EXISTS", target)
    if not target.parent.is_dir() or target.parent.is_symlink():
        issue("INVALID_TARGET_PARENT", target.parent)
    src, dst = source.resolve(), target.resolve()
    if src == dst or src in dst.parents or dst in src.parents:
        issue("SOURCE_TARGET_OVERLAP", target)

    for current, directories, filenames in os.walk(source, followlinks=False):
        for name in ["."] + directories + filenames if current == str(source) else directories + filenames:
            path = Path(current) if name == "." else Path(current) / name
            try:
                info = path.lstat()
                if stat.S_ISREG(info.st_mode):
                    count += 1
                    total_bytes += info.st_size
                    if info.st_nlink != 1:
                        issue("HARDLINK_UNSUPPORTED", path)
                elif not stat.S_ISDIR(info.st_mode):
                    issue("SYMLINK_OR_SPECIAL_UNSUPPORTED", path)
                if info.st_uid != os.geteuid() or info.st_gid != os.getegid():
                    issue("IDENTITY_UNSUPPORTED", path)
                if info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                    issue("SPECIAL_MODE_UNSUPPORTED", path)
                try:
                    if os.listxattr(path, follow_symlinks=False):
                        issue("XATTR_OR_ACL_UNSUPPORTED", path)
                except OSError:
                    issue("XATTR_INSPECTION_UNAVAILABLE", path)
            except OSError:
                issue("STAT_UNAVAILABLE", path)
    return count, total_bytes, findings


def main(argv=None):
    p = argparse.ArgumentParser(description="ODMM read-only local POSIX preflight")
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--target", type=Path, required=True)
    args = p.parse_args(argv)
    if not sys.platform.startswith("linux"):
        p.error("Linux required")
    count, total, findings = inspect(args.source, args.target)
    report = {"status": "BLOCKED" if findings else "READY_LOCAL_LAB_ONLY",
              "source": str(args.source), "target": str(args.target),
              "regular_files": count, "bytes": total, "findings": findings,
              "read_only": True, "production_nas_qualified": False}
    print(json.dumps(report, sort_keys=True, indent=2))
    return 2 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
