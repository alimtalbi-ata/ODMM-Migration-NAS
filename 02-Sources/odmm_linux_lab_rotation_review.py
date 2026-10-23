"""Read-only, bounded content inventory for HMAC rotation crash review.

POSIX laboratory only. SHA-256 is an UNTRUSTED comparison fingerprint, not
authentication, approval, a deletion plan, or permission to resume migration.
Author: Abdelhalim Talbi.
"""
import hashlib
import json
import os
import stat
from pathlib import Path

from odmm_linux_datamover_intents import _id
from odmm_linux_lab_external_anchor import _KEY_ID
from odmm_linux_lab_anchor_rotation import _receipt_name, _MAX_RECEIPT
from odmm_linux_lab_path_fence import pin_parent_chain
from odmm_linux_lab_rotation_recovery import inspect_rotation_publication

_MAX_ENTRIES = 33  # one final receipt and at most 32 pending files


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_nlink, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def _digest_leaf(dirfd, name):
    """Hash only a pinned regular inode; reject symlinks, races and oversize."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                 getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
                 dir_fd=dirfd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077 or
                before.st_nlink not in (1, 2) or before.st_size > _MAX_RECEIPT):
            raise ValueError("UNSAFE_RECEIPT_INODE")
        data = stream.read(_MAX_RECEIPT + 1)
        after = os.fstat(stream.fileno())
        if (len(data) > _MAX_RECEIPT or len(data) != before.st_size or
                _identity(before) != _identity(after)):
            raise ValueError("RECEIPT_CHANGED_DURING_READ")
        leaf = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        if _identity(leaf) != _identity(before):
            raise ValueError("RECEIPT_PATH_CHANGED")
    return {"name": name, "size": len(data), "device": before.st_dev,
            "inode": before.st_ino, "links": before.st_nlink,
            "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns,
            "sha256": hashlib.sha256(data).hexdigest()}


def review_rotation_orphans(anchor_dir, intent_id, to_key_id):
    """Produce a non-authoritative fingerprint manifest without any writes.

    Must be used *after* the operator has isolated the evidence. Never delete,
    rename or select a pending receipt automatically. The manifest hash is not
    an HMAC and must not be used to authenticate the contents.
    """
    denied = {"status": "UNSAFE_OR_UNAVAILABLE", "inventory_complete": False,
              "requires_operator_review": True, "authorizes_cleanup": False,
              "authorizes_resume": False, "nas_migration_qualified": False}
    try:
        intent_id = _id(intent_id)
        if not isinstance(to_key_id, str) or not _KEY_ID.fullmatch(to_key_id):
            return denied
        before = inspect_rotation_publication(anchor_dir, intent_id, to_key_id)
        if before["status"] == "UNSAFE_OR_UNAVAILABLE":
            return denied
        path = Path(anchor_dir) / _receipt_name(intent_id, to_key_id)
        prefix = path.name + ".pending-"
        with pin_parent_chain(path) as (dirfd, check):
            check()
            first = os.fstat(dirfd)
            with os.scandir(dirfd) as scan:
                names = sorted(entry.name for entry in scan
                               if entry.name == path.name or
                               entry.name.startswith(prefix))
            if len(names) > _MAX_ENTRIES:
                return denied
            files = [_digest_leaf(dirfd, name) for name in names]
            # Detect a mutation after hashing an earlier entry, even when
            # the directory itself was not modified by an in-place write.
            for item in files:
                current = os.stat(item["name"], dir_fd=dirfd, follow_symlinks=False)
                if (_identity(current) !=
                        (item["device"], item["inode"], item["links"],
                         item["size"], item["mtime_ns"], item["ctime_ns"])):
                    raise ValueError("RECEIPT_CHANGED_AFTER_DIGEST")
            last = os.fstat(dirfd)
            if _identity(first) != _identity(last):
                raise ValueError("RECEIPT_DIRECTORY_CHANGED")
            check()
        after = inspect_rotation_publication(anchor_dir, intent_id, to_key_id)
        if after != before:
            return denied
        final_count = sum(item["name"] == path.name for item in files)
        pending_count = len(files) - final_count
        expected_final = {"ABSENT": 0, "PENDING_ONLY": 0,
                          "FINAL_PRESENT_UNVERIFIED": 1,
                          "PUBLISHED_WITH_PENDING": 1, "UNRELATED_PENDING": 1}
        if before["status"] in expected_final and final_count != expected_final[before["status"]]:
            return denied
        if pending_count != before["pending_count"]:
            return denied
        if before["status"] == "PUBLISHED_WITH_PENDING":
            if (len(files) != 2 or files[0]["sha256"] != files[1]["sha256"] or
                    files[0]["inode"] != files[1]["inode"] or
                    files[0]["device"] != files[1]["device"]):
                return denied
        manifest = {"schema": "odmm.linux.lab.rotation.review.v1",
                    "status": before["status"], "intent_id": intent_id,
                    "to_key_id": to_key_id, "files": files}
        digest = hashlib.sha256(json.dumps(
            manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        return {**denied, "status": before["status"], "inventory_complete": True,
                "untrusted_inventory_sha256": digest, "manifest": manifest}
    except Exception:
        return denied
