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
from odmm_local_tree_preflight import inspect as preflight_inspect


def require_supported_metadata(path, *, regular):
    """Fail closed when this local prototype would silently lose metadata."""
    info = path.lstat()
    if info.st_uid != os.geteuid() or info.st_gid != os.getegid():
        raise ValueError("UNSUPPORTED_OWNER_OR_GROUP: " + str(path))
    if info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise ValueError("UNSUPPORTED_SPECIAL_MODE: " + str(path))
    if regular and info.st_nlink != 1:
        raise ValueError("UNSUPPORTED_HARDLINK: " + str(path))
    # Includes POSIX ACL xattrs where exposed by the filesystem.
    # If the filesystem cannot enumerate metadata, never assume it is empty.
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("XATTR_INSPECTION_FAILED: " + str(path)) from exc
    if names:
        raise ValueError("UNSUPPORTED_XATTR_OR_ACL: " + str(path))


def inventory(root):
    require_supported_metadata(root, regular=False)
    files = []
    dirs = []
    def traversal_error(exc):
        raise ValueError("SOURCE_TRAVERSAL_FAILED: " + str(exc)) from exc

    for current, subdirs, filenames in os.walk(
            root, topdown=True, followlinks=False, onerror=traversal_error):
        for name in subdirs + filenames:
            path = Path(current) / name
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                require_supported_metadata(path, regular=False)
                dirs.append(path.relative_to(root))
            elif stat.S_ISREG(mode):
                require_supported_metadata(path, regular=True)
                files.append(path.relative_to(root))
            else:
                raise ValueError("UNSUPPORTED_SYMLINK_OR_SPECIAL_FILE: " + str(path))
    return sorted(dirs), sorted(files)



def source_fingerprint(path):
    """Best-effort drift fence; not an atomic snapshot or NAS consistency proof."""
    info = path.stat(follow_symlinks=False)
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink)


def verify_tree(source, target, dirs, files):
    """Independent post-copy comparison; excludes ODMM's own journal."""
    import hashlib
    def digest(path):
        h = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()
    for relative in files:
        src, dst = source / relative, target / relative
        if not dst.is_file() or dst.is_symlink():
            raise RuntimeError("POST_COPY_FILE_MISSING_OR_UNSAFE: " + str(relative))
        if digest(src) != digest(dst):
            raise RuntimeError("POST_COPY_HASH_MISMATCH: " + str(relative))
        if stat.S_IMODE(src.stat().st_mode) != stat.S_IMODE(dst.stat().st_mode):
            raise RuntimeError("POST_COPY_FILE_MODE_MISMATCH: " + str(relative))
    for relative in dirs:
        src, dst = source / relative, target / relative
        if not dst.is_dir() or dst.is_symlink():
            raise RuntimeError("POST_COPY_DIRECTORY_MISSING_OR_UNSAFE: " + str(relative))
        if stat.S_IMODE(src.stat().st_mode) != stat.S_IMODE(dst.stat().st_mode):
            raise RuntimeError("POST_COPY_DIRECTORY_MODE_MISMATCH: " + str(relative))
    if stat.S_IMODE(source.stat().st_mode) != stat.S_IMODE(target.stat().st_mode):
        raise RuntimeError("POST_COPY_ROOT_MODE_MISMATCH")
    expected = {str(r) for r in files} | {str(r) for r in dirs}
    actual = set()
    for current, subdirs, filenames in os.walk(target, followlinks=False):
        for name in subdirs + filenames:
            rel = str((Path(current) / name).relative_to(target))
            if rel != ".odmm-local-journal.sqlite":
                actual.add(rel)
    if actual != expected:
        raise RuntimeError("POST_COPY_INVENTORY_MISMATCH")
    return len(files)


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
    count, total_bytes, findings = preflight_inspect(src, dst)
    if findings:
        print(json.dumps({"state": "BLOCKED_BY_PREFLIGHT", "findings": findings,
                          "target_created": False, "nas_migration_qualified": False},
                         sort_keys=True), file=sys.stderr)
        return 2
    try:
        dirs, files = inventory(src)
    except (ValueError, OSError) as exc:
        p.error(str(exc))
    # Recheck just before mutation; an inventory drift must not silently
    # omit new files or directories. This is not an atomic filesystem snapshot.
    _, _, second_findings = preflight_inspect(src, dst)
    try:
        dirs_again, files_again = inventory(src)
    except (ValueError, OSError) as exc:
        second_findings.append({"code": "SOURCE_METADATA_CHANGED", "path": str(src)})
        dirs_again, files_again = [], []
    if second_findings or dirs_again != dirs or files_again != files:
        print(json.dumps({"state": "BLOCKED_BY_PREFLIGHT", "findings": second_findings or
                          [{"code": "SOURCE_INVENTORY_CHANGED", "path": str(src)}],
                          "target_created": False, "nas_migration_qualified": False},
                         sort_keys=True), file=sys.stderr)
        return 2
    try:
        source_fingerprints = {relative: source_fingerprint(src / relative) for relative in files}
    except OSError as exc:
        print(json.dumps({"state": "BLOCKED_BY_PREFLIGHT", "findings":
                          [{"code": "SOURCE_STAT_FAILED", "path": str(src)}],
                          "target_created": False, "nas_migration_qualified": False}), file=sys.stderr)
        return 2
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
                if source_fingerprint(src / relative) != source_fingerprints[relative]:
                    raise RuntimeError("SOURCE_CHANGED_BEFORE_COPY")
                task = f"tree-{index}"
                token = claim(db, task, "local-tree-worker", 3600)
                result = run_lab_copy(
                    db, intent_id="tree-" + uuid.uuid4().hex, task_id=task,
                    owner="local-tree-worker", token=token,
                    source=src / relative, target=dst / relative)
                if result["state"] != "VERIFIED":
                    raise RuntimeError("NOT_VERIFIED")
                if source_fingerprint(src / relative) != source_fingerprints[relative]:
                    raise RuntimeError("SOURCE_CHANGED_DURING_COPY")
                copied += 1
        # Directory modes applied bottom-up after all children are written.
        for relative in reversed(dirs):
            os.chmod(dst / relative, stat.S_IMODE((src / relative).stat().st_mode))
        os.chmod(dst, stat.S_IMODE(src.stat().st_mode))
        verified = verify_tree(src, dst, dirs, files)
        for relative in files:
            if source_fingerprint(src / relative) != source_fingerprints[relative]:
                raise RuntimeError("SOURCE_CHANGED_DURING_VERIFICATION")
        print(json.dumps({"state": "VERIFIED", "files_copied": copied, "files_verified": verified,
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
