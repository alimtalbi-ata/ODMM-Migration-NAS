#!/usr/bin/env python3
"""Read-only NAS mount qualification preflight; never claims ACL fidelity.

Author: Abdelhalim Talbi.
"""
import argparse
import json
import os
import pathlib
import stat
import sys


def assess_mount(path, expected_type):
    path = pathlib.Path(path)
    result = {"path": str(path), "expected_type": expected_type,
              "status": "MANUAL_REVIEW_REQUIRED", "read_only": True,
              "authorizes_migration": False, "acl_qualified": False}
    if expected_type not in ("nfs", "nfs4", "cifs"):
        result["reason"] = "UNSUPPORTED_EXPECTED_TYPE"
        return result
    try:
        target = path.resolve(strict=True)
        if not target.is_dir():
            result["reason"] = "NOT_DIRECTORY"
            return result
        mountinfo = pathlib.Path("/proc/self/mountinfo").read_text()
        candidates = []
        for line in mountinfo.splitlines():
            left, sep, right = line.partition(" - ")
            if not sep:
                continue
            fields = left.split()
            details = right.split()
            if len(fields) < 5 or not details:
                continue
            mountpoint = pathlib.Path(fields[4].replace("\\040", " "))
            try:
                target.relative_to(mountpoint)
            except ValueError:
                continue
            candidates.append((len(mountpoint.parts), str(mountpoint), details[0]))
        if not candidates:
            result["reason"] = "MOUNT_NOT_FOUND"
            return result
        _, mountpoint, fstype = max(candidates)
        result.update({"mountpoint": mountpoint, "filesystem_type": fstype})
        if fstype != expected_type:
            result["reason"] = "FILESYSTEM_TYPE_MISMATCH"
        else:
            result["status"] = "MOUNT_IDENTIFIED"
            result["reason"] = "ACL_AND_IDENTITY_TESTS_STILL_REQUIRED"
    except (OSError, ValueError) as exc:
        result["reason"] = type(exc).__name__
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description="Read-only NAS mount identification")
    p.add_argument("--path", required=True)
    p.add_argument("--type", required=True, choices=("nfs", "nfs4", "cifs"))
    args = p.parse_args(argv)
    report = assess_mount(args.path, args.type)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "MOUNT_IDENTIFIED" else 2


if __name__ == "__main__":
    sys.exit(main())
