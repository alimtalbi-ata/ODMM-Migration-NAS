"""Crash-safe *registry-only* datamover intent journal; no NAS operations.

Author: Abdelhalim Talbi. Fail closed after uncertain external effects.
"""
import hashlib
import json
import sqlite3
import time

class IntentConflict(RuntimeError):
    pass

def initialize(connection):
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("""CREATE TABLE IF NOT EXISTS odmm_datamover_intents (
      intent_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, owner TEXT NOT NULL,
      fence_token INTEGER NOT NULL, payload_sha256 TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('PREPARED','IN_FLIGHT','UNCERTAIN','VERIFIED','ABORTED')),
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
    connection.commit()

def _id(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("INVALID_ID")
    return value

def _clock(now):
    now = int(time.time()) if now is None else now
    if type(now) is not int or now < 0:
        raise ValueError("INVALID_TIME")
    return now

def _transaction(db, work):
    db.execute("BEGIN IMMEDIATE")
    try:
        result = work()
        db.commit()
        return result
    except BaseException:
        db.rollback()
        raise

def prepare(db, intent_id, task_id, owner, token, payload, *, now=None):
    from odmm_linux_lease_registry import assert_current
    intent_id, task_id, owner = _id(intent_id), _id(task_id), _id(owner)
    if type(token) is not int or token < 1:
        raise ValueError("INVALID_TOKEN")
    if not isinstance(payload, dict):
        raise ValueError("INVALID_PAYLOAD")
    try:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("INVALID_PAYLOAD") from exc
    digest = hashlib.sha256(canonical).hexdigest()
    now = _clock(now)
    def work():
        assert_current(db, task_id, owner, token, now=now)
        row = db.execute("SELECT task_id,owner,fence_token,payload_sha256,state FROM odmm_datamover_intents WHERE intent_id=?", (intent_id,)).fetchone()
        if row:
            if row[:4] != (task_id, owner, token, digest):
                raise IntentConflict("INTENT_ID_REUSE")
            if row[4] != "PREPARED":
                raise IntentConflict("INTENT_ALREADY_ADVANCED")
            return digest
        db.execute("""INSERT INTO odmm_datamover_intents
          (intent_id,task_id,owner,fence_token,payload_sha256,state,created_at,updated_at)
          VALUES(?,?,?,?,?,'PREPARED',?,?)""", (intent_id, task_id, owner, token, digest, now, now))
        return digest
    return _transaction(db, work)

def mark_in_flight(db, intent_id, task_id, owner, token, *, now=None):
    from odmm_linux_lease_registry import assert_current
    intent_id, task_id, owner = _id(intent_id), _id(task_id), _id(owner)
    now = _clock(now)
    def work():
        assert_current(db, task_id, owner, token, now=now)
        row = db.execute("""UPDATE odmm_datamover_intents SET state='IN_FLIGHT',updated_at=?
          WHERE intent_id=? AND task_id=? AND owner=? AND fence_token=? AND state='PREPARED'""",
          (now, intent_id, task_id, owner, token))
        if row.rowcount != 1:
            raise IntentConflict("INTENT_NOT_PREPARED")
    _transaction(db, work)

def quarantine_unfinished(db, *, now=None):
    """At recovery, any IN_FLIGHT intent is UNCERTAIN, never automatically replayed."""
    now = _clock(now)
    def work():
        cursor = db.execute("""UPDATE odmm_datamover_intents SET state='UNCERTAIN',updated_at=?
          WHERE state='IN_FLIGHT'""", (now,))
        return cursor.rowcount
    return _transaction(db, work)

def unresolved(db):
    return db.execute("""SELECT intent_id,task_id,owner,fence_token,state
      FROM odmm_datamover_intents WHERE state IN ('IN_FLIGHT','UNCERTAIN')
      ORDER BY created_at,intent_id""").fetchall()
