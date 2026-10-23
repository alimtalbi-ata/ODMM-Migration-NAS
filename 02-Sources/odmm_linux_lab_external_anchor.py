"""External HMAC anchor for advisory SQLite inode evidence (Linux POSIX lab).

The anchor directory and HMAC key MUST be controlled independently of the
SQLite journal. Never store the key in Git, SQLite or an artifact. Anchors
cannot authorize replay, VERIFIED promotion, cleanup or NAS cutover.
Author: Abdelhalim Talbi.
"""
import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path

from odmm_linux_datamover_intents import _id
from odmm_linux_lab_path_fence import pin_parent_chain, PathFenceError

_SCHEMA = "odmm.linux.lab.identity.anchor.v1"
_KEY_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_MAX_ANCHOR = 32768


class AnchorError(RuntimeError):
    pass


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _filename(intent_id):
    return hashlib.sha256(_id(intent_id).encode("utf-8")).hexdigest() + ".anchor.json"


def _key(secret):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise AnchorError("INVALID_EXTERNAL_HMAC_KEY")
    return secret


def _evidence(db, intent_id):
    row = db.execute("""SELECT e.task_id,e.fence_token,e.payload_sha256,
        e.observation_json,e.observation_sha256,e.observed_at,
        i.task_id,i.fence_token,i.payload_sha256
        FROM odmm_lab_identity_evidence e
        JOIN odmm_datamover_intents i ON i.intent_id=e.intent_id
        WHERE e.intent_id=?""", (intent_id,)).fetchone()
    if row is None:
        raise AnchorError("EVIDENCE_NOT_FOUND")
    if row[:3] != row[6:]:
        raise AnchorError("EVIDENCE_BINDING_MISMATCH")
    if not hmac.compare_digest(hashlib.sha256(row[3].encode("utf-8")).hexdigest(), row[4]):
        raise AnchorError("EVIDENCE_DIGEST_MISMATCH")
    return {"intent_id": intent_id, "task_id": row[0], "fence_token": row[1],
            "payload_sha256": row[2], "observation_json": row[3],
            "observation_sha256": row[4], "observed_at": row[5]}


def create_anchor(db, intent_id, anchor_dir, *, key_id, secret):
    """Create an exclusive, fsynced external anchor; never overwrite an anchor."""
    intent_id = _id(intent_id)
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise AnchorError("INVALID_KEY_ID")
    secret = _key(secret)
    payload = _evidence(db, intent_id)
    signed = {"schema": _SCHEMA, "key_id": key_id, "evidence": payload}
    mac = hmac.new(secret, _json(signed).encode("utf-8"), hashlib.sha256).hexdigest()
    encoded = (_json({**signed, "hmac_sha256": mac}) + "\n").encode("utf-8")
    if len(encoded) > _MAX_ANCHOR:
        raise AnchorError("ANCHOR_TOO_LARGE")
    anchor = Path(anchor_dir) / _filename(intent_id)
    with pin_parent_chain(anchor) as (dirfd, check):
        fd = os.open(anchor.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dirfd)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(dirfd)
        check()
    return {"anchored": True, "key_id": key_id, "anchor_file": anchor.name,
            "authorizes_resume": False, "nas_migration_qualified": False}


def verify_anchor(db, intent_id, anchor_dir, *, key_resolver):
    """Fail-closed, read-only verification using an independently trusted resolver."""
    intent_id = _id(intent_id)
    try:
        if not callable(key_resolver):
            raise AnchorError("KEY_RESOLVER_REQUIRED")
        anchor = Path(anchor_dir) / _filename(intent_id)
        with pin_parent_chain(anchor) as (dirfd, check):
            check()
            fd = os.open(anchor.name, os.O_RDONLY | os.O_NOFOLLOW |
                         getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
                         dir_fd=dirfd)
            with os.fdopen(fd, "rb") as stream:
                st = os.fstat(stream.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_ANCHOR:
                    raise AnchorError("UNSAFE_ANCHOR_FILE")
                raw = stream.read(_MAX_ANCHOR + 1)
                if len(raw) > _MAX_ANCHOR:
                    raise AnchorError("ANCHOR_TOO_LARGE")
            check()
        doc = json.loads(raw)
        if not isinstance(doc, dict) or set(doc) != {"schema", "key_id", "evidence", "hmac_sha256"}:
            raise AnchorError("INVALID_ANCHOR")
        if doc["schema"] != _SCHEMA or not isinstance(doc["key_id"], str) or not _KEY_ID.fullmatch(doc["key_id"]):
            raise AnchorError("INVALID_ANCHOR")
        mac = doc["hmac_sha256"]
        if not isinstance(mac, str) or len(mac) != 64 or any(c not in "0123456789abcdef" for c in mac):
            raise AnchorError("INVALID_ANCHOR")
        secret = _key(key_resolver(doc["key_id"]))
        signed = {k: doc[k] for k in ("schema", "key_id", "evidence")}
        expected = hmac.new(secret, _json(signed).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            raise AnchorError("HMAC_MISMATCH")
        if doc["evidence"] != _evidence(db, intent_id):
            raise AnchorError("JOURNAL_CHANGED_SINCE_ANCHOR")
        return {"authenticated": True, "reason": "EXTERNAL_HMAC_MATCH",
                "key_id": doc["key_id"], "authorizes_resume": False,
                "nas_migration_qualified": False}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, AnchorError,
            PathFenceError, json.JSONDecodeError):
        return {"authenticated": False, "reason": "ANCHOR_MISSING_UNSAFE_OR_MISMATCH",
                "authorizes_resume": False, "nas_migration_qualified": False}
