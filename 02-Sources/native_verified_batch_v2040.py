"""V204.0 verified resumable batch orchestration for the native POSIX engine.

This wrapper strengthens post-copy verification. It is not a NAS vendor certification,
ACL-preservation guarantee, or cutover authorization.
"""
from __future__ import annotations

from pathlib import Path
from native_campaign_manifest_v2039 import load_manifest, run_batch
from native_tree_migration import NativeTreeMigration
from native_migration_errors import MigrationBlocked

SCHEMA = "odmm-native-verified-batch-v2040"

def run_verified_batch(source, target, database, manifest_path, *, offset=0, limit=None):
    """Run one explicit manifest batch, then verify every selected file with the native engine.

    Stops at the first copy or verification failure. The function never authorizes cutover.
    """
    payload = load_manifest(manifest_path)
    if str(Path(source).resolve()) != payload["source"] or str(Path(target).resolve()) != payload["target"]:
        raise MigrationBlocked("CAMPAIGN_ROOT_MISMATCH")
    if type(offset) is not int or offset < 0 or offset > len(payload["files"]):
        raise ValueError("INVALID_OFFSET")
    if limit is not None and (type(limit) is not int or limit < 0):
        raise ValueError("INVALID_LIMIT")
    stop = len(payload["files"]) if limit is None else min(len(payload["files"]), offset + limit)
    selected = payload["files"][offset:stop]
    copied = run_batch(source, target, database, manifest_path, offset=offset, limit=limit)
    verified = []
    with NativeTreeMigration(source, target, database) as tree:
        for rel in selected:
            verified.append(tree.engine.verify(rel))
    return {
        "schema": SCHEMA,
        "status": "BATCH_VERIFIED_POSIX_SUBSET_ONLY",
        "offset": offset,
        "next_offset": stop,
        "inventory_count": len(payload["files"]),
        "processed_count": len(selected),
        "copy_results": copied["results"],
        "verification_results": verified,
        "content_and_basic_posix_metadata_verified": True,
        "acl_fidelity_verified": False,
        "cutover_authorized": False,
    }
