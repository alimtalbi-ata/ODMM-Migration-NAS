"""Cooperative interprocess serialization of authenticated IPC pin rotation.

Fail-closed: ambiguous checkpoint/audit/pin divergence is reported, never repaired.
Legacy direct entry points are not intercepted; deployment isolation is required.
"""
import sqlite3
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError


class SerializedAuthenticatedRotation:
    def __init__(self, facade, *, lock_path):
        self.facade = facade
        self.lock_path = Path(lock_path)
        paths = (facade.path, facade.controller.gate_path, facade.controller.pin.path)
        if self.lock_path.resolve() in [p.resolve() for p in paths]:
            raise IdentityPinError('ROTATION_LOCK_PATH_COLLISION')
        if self.lock_path.is_symlink():
            raise IdentityPinError('ROTATION_LOCK_SYMLINK_FORBIDDEN')

    def _locked(self, operation):
        if self.lock_path.is_symlink():
            raise IdentityPinError('ROTATION_LOCK_SYMLINK_FORBIDDEN')
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(str(self.lock_path), timeout=0.2, isolation_level=None)
        try:
            db.execute('PRAGMA busy_timeout=200')
            try:
                db.execute('BEGIN IMMEDIATE')
            except sqlite3.OperationalError as exc:
                raise IdentityPinError('ROTATION_LOCK_BUSY') from exc
            result = operation()
            db.execute('COMMIT')
            return result
        except BaseException:
            if db.in_transaction:
                db.execute('ROLLBACK')
            raise
        finally:
            db.close()

    def inspect(self):
        return self._locked(self.facade.inspect)

    def enroll_checkpoint(self, *, operator_confirmed):
        return self._locked(lambda: self.facade.enroll_checkpoint(operator_confirmed=operator_confirmed))

    def rotate(self, **kwargs):
        def operation():
            if self.facade.inspect()['status'] != 'CHECKPOINT_VERIFIED':
                raise IdentityPinError('ROTATION_RECONCILIATION_REQUIRED')
            return self.facade.rotate(**kwargs)
        return self._locked(operation)

    def reconciliation_report(self):
        """Non-mutating report; no token, recovery, or automatic re-anchoring."""
        def operation():
            status = self.facade.inspect()['status']
            return {'status': status,
                    'manual_review_required': status != 'CHECKPOINT_VERIFIED',
                    'automatic_repair_authorized': False,
                    'execution_authorized': False,
                    'cutover_authorized': False}
        return self._locked(operation)
