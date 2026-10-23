"""Immutable dual-HMAC rollover receipt for Linux POSIX laboratory evidence.

This is an advisory continuity check, not a distributed lease or migration
authorization. Old keys must remain available for verification while retired;
revocation fails closed. The resolver and policy MUST live outside SQLite.
Author: Abdelhalim Talbi.
"""
import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path

from odmm_linux_datamover_intents import _id
from odmm_linux_lab_external_anchor import (
    AnchorError, _evidence, _filename, _json, _key, _KEY_ID, _MAX_ANCHOR,
    verify_anchor,
)
from odmm_linux_lab_path_fence import pin_parent_chain

_SCHEMA = "odmm.linux.lab.identity.rotation.v1"
_MAX_RECEIPT = 32768


def _receipt_name(intent_id, to_key_id):
    suffix = hashlib.sha256(to_key_id.encode("utf-8")).hexdigest()
    return _filename(intent_id) + "." + suffix + ".rotation.json"


def _read_regular(path, limit):
    """Read a pinned, single-link regular file without following symlinks."""
    with pin_parent_chain(path) as (dirfd, check):
        check()
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW |
                     getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
                     dir_fd=dirfd)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    before.st_size > limit or before.st_mode & 0o077):
                raise AnchorError("UNSAFE_ROTATION_FILE")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if len(raw) > limit or (before.st_dev, before.st_ino, before.st_size,
                                    before.st_mtime_ns, before.st_ctime_ns) != (
                                        after.st_dev, after.st_ino, after.st_size,
                                        after.st_mtime_ns, after.st_ctime_ns):
                raise AnchorError("ROTATION_FILE_CHANGED")
            leaf = os.stat(path.name, dir_fd=dirfd, follow_symlinks=False)
            if (leaf.st_dev, leaf.st_ino) != (before.st_dev, before.st_ino):
                raise AnchorError("ROTATION_PATH_CHANGED")
        check()
        return raw


def _signed(intent_id, from_key_id, to_key_id, anchor_bytes, evidence):
    return {
        "schema": _SCHEMA,
        "intent_id": intent_id,
        "from_key_id": from_key_id,
        "to_key_id": to_key_id,
        "original_anchor_sha256": hashlib.sha256(anchor_bytes).hexdigest(),
        "evidence_sha256": hashlib.sha256(_json(evidence).encode("utf-8")).hexdigest(),
    }


def create_rotation(db, intent_id, anchor_dir, *, from_key_id, to_key_id,
                    old_secret, new_secret):
    """Write a non-overwritable receipt signed by BOTH old and new keys.

    This only rolls over the evidence authentication key. It does not change
    the original anchor, SQLite, intent state or migration execution rights.
    """
    intent_id = _id(intent_id)
    if (not isinstance(from_key_id, str) or not _KEY_ID.fullmatch(from_key_id) or
            not isinstance(to_key_id, str) or not _KEY_ID.fullmatch(to_key_id) or
            from_key_id == to_key_id):
        raise AnchorError("INVALID_ROTATION_KEY_IDS")
    old_secret, new_secret = _key(old_secret), _key(new_secret)
    if hmac.compare_digest(old_secret, new_secret):
        raise AnchorError("ROTATION_REQUIRES_DISTINCT_KEYS")
    old = verify_anchor(db, intent_id, anchor_dir,
                        key_resolver=lambda key_id: old_secret if key_id == from_key_id else None)
    if not old["authenticated"] or old.get("key_id") != from_key_id:
        raise AnchorError("ORIGINAL_ANCHOR_NOT_AUTHENTICATED")
    root = Path(anchor_dir)
    anchor_bytes = _read_regular(root / _filename(intent_id), _MAX_ANCHOR)
    signed = _signed(intent_id, from_key_id, to_key_id, anchor_bytes,
                     _evidence(db, intent_id))
    payload = _json(signed).encode("utf-8")
    receipt = {**signed,
               "old_hmac_sha256": hmac.new(old_secret, payload, hashlib.sha256).hexdigest(),
               "new_hmac_sha256": hmac.new(new_secret, payload, hashlib.sha256).hexdigest()}
    encoded = (_json(receipt) + "\n").encode("utf-8")
    if len(encoded) > _MAX_RECEIPT:
        raise AnchorError("ROTATION_RECEIPT_TOO_LARGE")
    path = root / _receipt_name(intent_id, to_key_id)
    # A final receipt must never be visible until its entire payload is
    # written and fsynced. An exclusive hard link publishes it without
    # overwriting an existing receipt (unlike os.replace).
    stage_name = path.name + ".pending-" + secrets.token_hex(16)
    with pin_parent_chain(path) as (dirfd, check):
        check()
        fd = os.open(stage_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600,
                     dir_fd=dirfd)
        owned = os.fstat(fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            check()
            staged = os.stat(stage_name, dir_fd=dirfd, follow_symlinks=False)
            if (not stat.S_ISREG(staged.st_mode) or staged.st_nlink != 1 or
                    staged.st_size != len(encoded) or staged.st_mode & 0o077 or
                    (staged.st_dev, staged.st_ino) != (owned.st_dev, owned.st_ino)):
                raise AnchorError("ROTATION_STAGE_CHANGED")
            os.link(stage_name, path.name, src_dir_fd=dirfd,
                    dst_dir_fd=dirfd, follow_symlinks=False)
            published = os.stat(path.name, dir_fd=dirfd, follow_symlinks=False)
            if (published.st_dev, published.st_ino) != (owned.st_dev, owned.st_ino):
                raise AnchorError("ROTATION_PUBLISHED_INODE_CHANGED")
            os.fsync(dirfd)
            check()
        finally:
            # Only remove our own staging inode; never unlink a substituted
            # path or the final receipt. A SIGKILL can leave a pending file:
            # verification ignores it and remains fail-closed.
            try:
                current = os.stat(stage_name, dir_fd=dirfd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                    os.unlink(stage_name, dir_fd=dirfd)
                    os.fsync(dirfd)
    return {"rotation_recorded": True, "to_key_id": to_key_id,
            "authorizes_resume": False, "nas_migration_qualified": False}


def verify_rotation(db, intent_id, anchor_dir, *, from_key_id, to_key_id,
                    key_resolver, key_status):
    """Require dual signatures and external policy: old active/retired, new active.

    Revoked/unknown keys, missing receipts, unavailable providers and tampering
    all fail closed. Never promote UNCERTAIN or authorize automatic replay.
    """
    denied = {"authenticated": False, "reason": "ROTATION_UNAVAILABLE_OR_INVALID",
              "authorizes_resume": False, "nas_migration_qualified": False}
    try:
        intent_id = _id(intent_id)
        if (not callable(key_resolver) or not callable(key_status) or
                not isinstance(from_key_id, str) or not _KEY_ID.fullmatch(from_key_id) or
                not isinstance(to_key_id, str) or not _KEY_ID.fullmatch(to_key_id) or
                from_key_id == to_key_id):
            return denied
        if key_status(from_key_id) not in ("active", "retired") or key_status(to_key_id) != "active":
            return denied
        old_secret = _key(key_resolver(from_key_id))
        new_secret = _key(key_resolver(to_key_id))
        original = verify_anchor(
            db, intent_id, anchor_dir,
            key_resolver=lambda key_id: old_secret if key_id == from_key_id else None)
        if not original["authenticated"] or original.get("key_id") != from_key_id:
            return denied
        root = Path(anchor_dir)
        anchor_bytes = _read_regular(root / _filename(intent_id), _MAX_ANCHOR)
        receipt_bytes = _read_regular(root / _receipt_name(intent_id, to_key_id), _MAX_RECEIPT)
        doc = json.loads(receipt_bytes)
        signed = _signed(intent_id, from_key_id, to_key_id, anchor_bytes,
                         _evidence(db, intent_id))
        if (not isinstance(doc, dict) or set(doc) != set(signed) |
                {"old_hmac_sha256", "new_hmac_sha256"} or
                any(doc[k] != v for k, v in signed.items())):
            return denied
        payload = _json(signed).encode("utf-8")
        for field, secret in (("old_hmac_sha256", old_secret),
                              ("new_hmac_sha256", new_secret)):
            mac = doc[field]
            if (not isinstance(mac, str) or len(mac) != 64 or
                    not hmac.compare_digest(
                        hmac.new(secret, payload, hashlib.sha256).hexdigest(), mac)):
                return denied
        return {"authenticated": True, "reason": "DUAL_HMAC_ROTATION_VERIFIED",
                "from_key_id": from_key_id, "to_key_id": to_key_id,
                "authorizes_resume": False, "nas_migration_qualified": False}
    except Exception:
        return denied
