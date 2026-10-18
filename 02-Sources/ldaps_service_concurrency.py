"""SQLite-backed interprocess service gate, with OS crash-released write locks.

Only cooperatively gated callers are serialized. Use a dedicated SQLite file on
local storage; do not share a single connection between threads/processes.
"""
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

class ServiceConcurrencyError(RuntimeError): pass

class InterprocessServiceGate:
    def __init__(self, path, *, timeout=0.25):
        self.path=Path(path)
        if not self.path.parent.exists():
            raise ServiceConcurrencyError('GATE_DIRECTORY_MISSING')
        if not isinstance(timeout,(float,int)) or isinstance(timeout,bool) or timeout<0:
            raise ServiceConcurrencyError('INVALID_GATE_TIMEOUT')
        self.timeout=timeout

    @contextmanager
    def exclusive(self):
        # Connection is process-local and is never inherited from a parent.
        db=sqlite3.connect(str(self.path),timeout=self.timeout,isolation_level=None)
        acquired=False
        try:
            db.execute('PRAGMA busy_timeout=%d' % int(self.timeout*1000))
            try:
                db.execute('BEGIN EXCLUSIVE')
                acquired=True
            except sqlite3.OperationalError as exc:
                raise ServiceConcurrencyError('SERVICE_GATE_BUSY') from exc
            yield
            db.execute('COMMIT')
        except BaseException:
            if acquired and db.in_transaction:db.execute('ROLLBACK')
            raise
        finally:
            db.close()
