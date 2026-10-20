"""Transactional Linux datamover task leasing (local SQLite prototype).

No NAS IO. This is a single-registry primitive, NOT distributed consensus or HA.
Author: Abdelhalim Talbi.
"""
import sqlite3
import time

class LeaseConflict(RuntimeError):
    pass

def initialize(connection):
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("""CREATE TABLE IF NOT EXISTS odmm_leases (
        task_id TEXT PRIMARY KEY, owner TEXT NOT NULL, token INTEGER NOT NULL,
        expires_at INTEGER NOT NULL, state TEXT NOT NULL
        CHECK (state IN ('CLAIMED', 'RELEASED')))""")
    connection.execute("""CREATE TABLE IF NOT EXISTS odmm_lease_fence (
        id INTEGER PRIMARY KEY CHECK (id=1), next_token INTEGER NOT NULL)""")
    connection.execute("INSERT OR IGNORE INTO odmm_lease_fence(id,next_token) VALUES(1,1)")
    connection.commit()

def _identity(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("INVALID_LEASE_ID")
    return value

def _transaction(connection, operation):
    connection.execute("BEGIN IMMEDIATE")
    try:
        result = operation()
        connection.commit()
        return result
    except BaseException:
        connection.rollback()
        raise

def claim(connection, task_id, owner, ttl_seconds, *, now=None):
    task_id, owner = _identity(task_id), _identity(owner)
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 86400:
        raise ValueError("INVALID_TTL")
    now = int(time.time()) if now is None else now
    if type(now) is not int or now < 0:
        raise ValueError("INVALID_TIME")
    def work():
        row = connection.execute("SELECT owner, token, expires_at, state FROM odmm_leases WHERE task_id=?", (task_id,)).fetchone()
        if row and row[3] == "CLAIMED" and row[2] > now:
            raise LeaseConflict("TASK_ALREADY_OWNED")
        token = connection.execute("SELECT next_token FROM odmm_lease_fence WHERE id=1").fetchone()[0]
        connection.execute("UPDATE odmm_lease_fence SET next_token=? WHERE id=1", (token + 1,))
        connection.execute("""INSERT INTO odmm_leases(task_id,owner,token,expires_at,state)
            VALUES(?,?,?,?, 'CLAIMED') ON CONFLICT(task_id) DO UPDATE SET
            owner=excluded.owner,token=excluded.token,expires_at=excluded.expires_at,state='CLAIMED'""",
            (task_id, owner, token, now + ttl_seconds))
        return token
    return _transaction(connection, work)

def renew(connection, task_id, owner, token, ttl_seconds, *, now=None):
    task_id, owner = _identity(task_id), _identity(owner)
    if type(token) is not int or token < 1 or type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 86400:
        raise ValueError("INVALID_LEASE")
    now = int(time.time()) if now is None else now
    if type(now) is not int or now < 0:
        raise ValueError("INVALID_TIME")
    def work():
        cursor = connection.execute("""UPDATE odmm_leases SET expires_at=?
            WHERE task_id=? AND owner=? AND token=? AND state='CLAIMED' AND expires_at>?""",
            (now + ttl_seconds, task_id, owner, token, now))
        if cursor.rowcount != 1:
            raise LeaseConflict("STALE_OR_EXPIRED_LEASE")
        return token
    return _transaction(connection, work)

def release(connection, task_id, owner, token, *, now=None):
    task_id, owner = _identity(task_id), _identity(owner)
    if type(token) is not int or token < 1:
        raise ValueError("INVALID_TOKEN")
    now = int(time.time()) if now is None else now
    if type(now) is not int or now < 0:
        raise ValueError("INVALID_TIME")
    def work():
        cursor = connection.execute("""UPDATE odmm_leases SET state='RELEASED'
            WHERE task_id=? AND owner=? AND token=? AND state='CLAIMED' AND expires_at>?""",
            (task_id, owner, token, now))
        if cursor.rowcount != 1:
            raise LeaseConflict("STALE_OR_EXPIRED_LEASE")
    _transaction(connection, work)

def assert_current(connection, task_id, owner, token, *, now=None):
    """Fail closed before a guarded operation; not a NAS-side atomic fence."""
    task_id, owner = _identity(task_id), _identity(owner)
    if type(token) is not int or token < 1:
        raise ValueError("INVALID_TOKEN")
    now = int(time.time()) if now is None else now
    if type(now) is not int or now < 0:
        raise ValueError("INVALID_TIME")
    row = connection.execute(
        "SELECT 1 FROM odmm_leases WHERE task_id=? AND owner=? AND token=? AND state='CLAIMED' AND expires_at>?",
        (task_id, owner, token, now),
    ).fetchone()
    if row is None:
        raise LeaseConflict("STALE_OR_EXPIRED_LEASE")
    return True

def guarded_registry_effect(connection, task_id, owner, token, operation, *, now=None):
    """Atomic lease check plus SQL registry mutation in one BEGIN IMMEDIATE transaction.

    The callback receives the active SQLite connection. It MUST perform only
    SQL writes to this registry, not filesystem/network/NAS effects.
    """
    if not callable(operation):
        raise TypeError("INVALID_REGISTRY_OPERATION")
    def work():
        assert_current(connection, task_id, owner, token, now=now)
        return operation(connection)
    return _transaction(connection, work)
