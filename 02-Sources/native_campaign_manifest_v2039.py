"""Immutable inventory manifests for resumable native POSIX migration campaigns.

This is a local POSIX prototype. It does not preserve NAS ACLs/ADS or authorize cutover.
"""
import hashlib
import json
import os
import tempfile
from pathlib import Path
from native_tree_migration import NativeTreeMigration
from native_migration_errors import MigrationBlocked

SCHEMA = "odmm-native-campaign-manifest-v2039"

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def create_manifest(source, target, database, manifest_path):
    """Capture one ordered inventory and publish a create-only, checksummed manifest."""
    out = Path(manifest_path)
    if out.exists() or out.is_symlink():
        raise MigrationBlocked("MANIFEST_ALREADY_EXISTS")
    with NativeTreeMigration(source, target, database) as tree:
        paths = tree.inventory()
        payload = {
            "schema": SCHEMA,
            "source": str(tree.engine.source),
            "target": str(tree.engine.target),
            "files": paths,
            "count": len(paths),
        }
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    envelope = {"payload": payload, "sha256": digest}
    out.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive create prevents overwriting a pre-existing campaign manifest.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(out, flags, 0o600)
    try:
        data = _canonical(envelope) + b"\n"
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(out.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return {"status": "MANIFEST_CREATED", "count": len(paths), "sha256": digest,
            "cutover_authorized": False, "acl_fidelity_verified": False}

def load_manifest(manifest_path):
    p = Path(manifest_path)
    if p.is_symlink() or not p.is_file():
        raise MigrationBlocked("MANIFEST_MISSING_OR_UNSAFE")
    try:
        envelope = json.loads(p.read_text(encoding="utf-8"))
        payload = envelope["payload"]
        digest = envelope["sha256"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise MigrationBlocked("MANIFEST_INVALID") from exc
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise MigrationBlocked("MANIFEST_SCHEMA_INVALID")
    if hashlib.sha256(_canonical(payload)).hexdigest() != digest:
        raise MigrationBlocked("MANIFEST_INTEGRITY_FAILURE")
    files = payload.get("files")
    if (not isinstance(files, list) or payload.get("count") != len(files)
            or any(not isinstance(x, str) or not x or x.startswith("/") or "\\" in x
                   or any(part in ("", ".", "..") for part in x.split("/")) for x in files)
            or files != sorted(set(files))):
        raise MigrationBlocked("MANIFEST_INVENTORY_INVALID")
    return payload

def run_batch(source, target, database, manifest_path, *, offset=0, limit=None):
    """Run a bounded batch from the immutable inventory; resume by explicit offset."""
    payload = load_manifest(manifest_path)
    if type(offset) is not int or offset < 0 or offset > len(payload["files"]):
        raise ValueError("INVALID_OFFSET")
    if limit is not None and (type(limit) is not int or limit < 0):
        raise ValueError("INVALID_LIMIT")
    with NativeTreeMigration(source, target, database) as tree:
        if str(tree.engine.source) != payload["source"] or str(tree.engine.target) != payload["target"]:
            raise MigrationBlocked("CAMPAIGN_ROOT_MISMATCH")
        current = tree.inventory()
        if current != payload["files"]:
            raise MigrationBlocked("SOURCE_INVENTORY_DRIFT")
        stop = len(current) if limit is None else min(len(current), offset + limit)
        results = [tree.engine.copy(rel) for rel in payload["files"][offset:stop]]
    return {"status": "BATCH_COMPLETE_POSIX_SUBSET_ONLY", "offset": offset,
            "next_offset": stop, "inventory_count": len(payload["files"]),
            "processed_count": len(results), "results": results,
            "cutover_authorized": False, "acl_fidelity_verified": False}
