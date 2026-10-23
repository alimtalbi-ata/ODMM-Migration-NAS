"""Durable, advisory POSIX inode observations for the isolated Linux copy lab.

Observations are immutable and never authorize replay, deletion or promotion of
UNCERTAIN intents. SQLite durability requires WAL and synchronous=FULL on the
caller's connection. Not a distributed NFS/SMB fencing protocol.
Author: Abdelhalim Talbi.
"""
import hashlib
import hmac
import json
import os
import stat
from pathlib import Path

from odmm_linux_datamover_intents import _id, _transaction


class IdentityEvidenceConflict(RuntimeError):
    pass


IDENTITY_KEYS = (
    "source_dev", "source_ino", "source_parent_dev", "source_parent_ino",
    "target_dev", "target_ino", "target_parent_dev", "target_parent_ino",
    "size", "sha256",
)


def initialize(db):
    db.execute("""CREATE TABLE IF NOT EXISTS odmm_lab_identity_evidence (
        intent_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        fence_token INTEGER NOT NULL,
        payload_sha256 TEXT NOT NULL,
        observation_json TEXT NOT NULL,
        observation_sha256 TEXT NOT NULL,
        observed_at INTEGER NOT NULL
    )""")
    db.commit()


def _canonical(observation):
    if not isinstance(observation, dict) or set(observation) != set(IDENTITY_KEYS):
        raise ValueError("INVALID_IDENTITY_EVIDENCE")
    for key in IDENTITY_KEYS:
        value = observation[key]
        if key == "sha256":
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("INVALID_IDENTITY_DIGEST")
        elif type(value) is not int or value < 0:
            raise ValueError("INVALID_IDENTITY_NUMBER")
    return json.dumps(observation, sort_keys=True, separators=(",", ":"), allow_nan=False)


def record_identity(db, *, intent_id, task_id, owner, token, payload_sha256, observation, now=None):
    """Persist proof before VERIFIED; a crash afterwards remains UNCERTAIN."""
    from odmm_linux_lease_registry import assert_current
    from odmm_linux_datamover_intents import _clock
    intent_id, task_id, owner = _id(intent_id), _id(task_id), _id(owner)
    if type(token) is not int or token < 1:
        raise ValueError("INVALID_TOKEN")
    if not isinstance(payload_sha256, str) or len(payload_sha256) != 64 or any(c not in "0123456789abcdef" for c in payload_sha256):
        raise ValueError("INVALID_DIGEST")
    canonical = _canonical(observation)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    now = _clock(now)

    def work():
        assert_current(db, task_id, owner, token, now=now)
        row = db.execute("""SELECT payload_sha256 FROM odmm_datamover_intents
            WHERE intent_id=? AND task_id=? AND owner=? AND fence_token=? AND state='IN_FLIGHT'""",
            (intent_id, task_id, owner, token)).fetchone()
        if row is None or not hmac.compare_digest(row[0], payload_sha256):
            raise IdentityEvidenceConflict("INTENT_NOT_IN_FLIGHT_OR_PAYLOAD_CHANGED")
        if db.execute("SELECT 1 FROM odmm_lab_identity_evidence WHERE intent_id=?", (intent_id,)).fetchone():
            raise IdentityEvidenceConflict("IDENTITY_EVIDENCE_IMMUTABLE")
        db.execute("""INSERT INTO odmm_lab_identity_evidence
            (intent_id,task_id,fence_token,payload_sha256,observation_json,observation_sha256,observed_at)
            VALUES (?,?,?,?,?,?,?)""",
            (intent_id, task_id, token, payload_sha256, canonical, digest, now))
        return digest
    return _transaction(db, work)


def inspect_identity(db, intent_id, source, target):
    """Read-only advisory comparison; matching inode numbers do not prove ownership."""
    intent_id = _id(intent_id)
    table = db.execute("""SELECT 1 FROM sqlite_master
        WHERE type='table' AND name='odmm_lab_identity_evidence'""").fetchone()
    if not table:
        return {"recorded": False, "identity_matches": None, "reason": "NO_DURABLE_OBSERVATION"}
    row = db.execute("""SELECT task_id,fence_token,payload_sha256,observation_json,observation_sha256
        FROM odmm_lab_identity_evidence WHERE intent_id=?""", (intent_id,)).fetchone()
    if row is None:
        return {"recorded": False, "identity_matches": None, "reason": "NO_DURABLE_OBSERVATION"}
    intent = db.execute("""SELECT task_id,fence_token,payload_sha256
        FROM odmm_datamover_intents WHERE intent_id=?""", (intent_id,)).fetchone()
    if intent != row[:3]:
        return {"recorded": True, "identity_matches": False, "reason": "JOURNAL_BINDING_MISMATCH"}
    canonical = row[3]
    if not hmac.compare_digest(hashlib.sha256(canonical.encode("utf-8")).hexdigest(), row[4]):
        return {"recorded": True, "identity_matches": False, "reason": "JOURNAL_DIGEST_MISMATCH"}
    try:
        observation = json.loads(canonical)
        if _canonical(observation) != canonical:
            raise ValueError("NONCANONICAL")
        paths = {"source": Path(source), "target": Path(target)}
        for label, path in paths.items():
            parent = path.parent.lstat()
            leaf = path.lstat()
            if not stat.S_ISDIR(parent.st_mode) or not stat.S_ISREG(leaf.st_mode):
                raise ValueError("UNSAFE_FILE_TYPE")
            if (parent.st_dev, parent.st_ino, leaf.st_dev, leaf.st_ino) != (
                observation[label + "_parent_dev"], observation[label + "_parent_ino"],
                observation[label + "_dev"], observation[label + "_ino"]):
                return {"recorded": True, "identity_matches": False, "reason": "PATH_IDENTITY_CHANGED"}
    except (OSError, ValueError, KeyError, TypeError):
        return {"recorded": True, "identity_matches": False, "reason": "IDENTITY_UNAVAILABLE_OR_UNSAFE"}
    return {"recorded": True, "identity_matches": True, "reason": "LOCAL_INODE_IDENTITIES_MATCH",
            "nas_migration_qualified": False, "authorizes_resume": False}
