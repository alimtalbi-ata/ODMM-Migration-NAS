#!/usr/bin/env python3
"""Read-only NAS mount qualification preflight; never claims ACL fidelity.

Author: Abdelhalim Talbi.
"""
import argparse
import json
import os
import pathlib
import re
import sys


def _unescape_mount_field(value):
    """Decode octal escapes used by procfs mountinfo fields."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)


def find_mount(target, mountinfo_text):
    """Return the deepest mount containing target, or None."""
    target = pathlib.Path(os.path.abspath(target))
    candidates = []
    for line in mountinfo_text.splitlines():
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        fields = left.split()
        details = right.split()
        if len(fields) < 6 or len(details) < 3:
            continue
        mountpoint = pathlib.Path(_unescape_mount_field(fields[4]))
        try:
            target.relative_to(mountpoint)
        except ValueError:
            continue
        mount_options = set(fields[5].split(","))
        super_options = set(details[2].split(","))
        candidates.append((len(mountpoint.parts), str(mountpoint),
                           details[0], _unescape_mount_field(details[1]),
                           mount_options, super_options))
    if not candidates:
        return None
    _, mountpoint, fstype, source, mount_options, super_options = max(
        candidates, key=lambda item: item[0])
    has_ro = "ro" in mount_options
    has_rw = "rw" in mount_options
    mount_read_only = True if has_ro and not has_rw else (
        False if has_rw and not has_ro else None)
    return {"mountpoint": mountpoint, "filesystem_type": fstype,
            "source": source, "mount_options": sorted(mount_options),
            "mount_read_only": mount_read_only,
            "super_options": sorted(super_options)}


def matches_expected_type(mounted, expected_type):
    fstype = mounted["filesystem_type"]
    options = set(mounted["super_options"])
    if expected_type == "nfs4":
        return fstype == "nfs4" or (fstype == "nfs" and
               any(opt in ("vers=4", "vers=4.0", "vers=4.1", "vers=4.2")
                   for opt in options))
    if expected_type == "nfs":
        return fstype == "nfs" and not any(opt.startswith("vers=4") for opt in options)
    if expected_type == "cifs":
        return fstype == "cifs"
    return False


def assess_mount(path, expected_type, mountinfo_text=None):
    path = pathlib.Path(path)
    result = {"path": str(path), "expected_type": expected_type,
              "status": "MANUAL_REVIEW_REQUIRED",
              "read_only": True, "inspection_read_only": True,
              "mount_read_only": None,
              "authorizes_migration": False, "acl_qualified": False}
    if expected_type not in ("nfs", "nfs4", "cifs"):
        result["reason"] = "UNSUPPORTED_EXPECTED_TYPE"
        return result
    try:
        target = path.resolve(strict=True)
        if not target.is_dir():
            result["reason"] = "NOT_DIRECTORY"
            return result
        if mountinfo_text is None:
            mountinfo_text = pathlib.Path("/proc/self/mountinfo").read_text()
        mounted = find_mount(target, mountinfo_text)
        if mounted is None:
            result["reason"] = "MOUNT_NOT_FOUND"
            return result
        result.update(mounted)
        if mounted["mount_read_only"] is None:
            result["reason"] = "MOUNT_ACCESS_MODE_AMBIGUOUS"
        elif not matches_expected_type(mounted, expected_type):
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
