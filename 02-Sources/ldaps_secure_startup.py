"""Fail-closed startup attestation for a cooperatively isolated RBAC service.

This checks local SQLite evidence and explicit deployment exposure declarations.
It does NOT sandbox Python objects or disable legacy APIs globally.
"""
import os
import sqlite3
from pathlib import Path
from ldaps_transition_reconciliation import TransitionReconciliationError

class SecureStartupError(TransitionReconciliationError):
    pass

class SecureStartupAttestation:
    def __init__(self, service, *, legacy_routes_exposed, direct_database_exposed):
        from ldaps_secure_service import SecureRoleService
        if not isinstance(service, SecureRoleService):
            raise SecureStartupError('SECURE_SERVICE_REQUIRED')
        if type(legacy_routes_exposed) is not bool or type(direct_database_exposed) is not bool:
            raise SecureStartupError('EXPOSURE_DECLARATION_REQUIRED')
        self.service=service
        self.legacy_routes_exposed=legacy_routes_exposed
        self.direct_database_exposed=direct_database_exposed

    def verify(self):
        if self.legacy_routes_exposed or self.direct_database_exposed:
            raise SecureStartupError('UNSAFE_LEGACY_EXPOSURE')
        if not self.service._SecureRoleService__strict:
            raise SecureStartupError('STRICT_MODE_REQUIRED')
        gate=self.service._SecureRoleService__gate
        if gate is None:
            raise SecureStartupError('INTERPROCESS_GATE_REQUIRED')
        if gate.path.is_symlink() or not gate.path.parent.is_dir():
            raise SecureStartupError('UNSAFE_GATE_PATH')
        # sqlite integrity_check is a consistency test, not a cryptographic proof.
        admin=self.service._SecureRoleService__admin
        with self.service._SecureRoleService__lock, gate.exclusive():
            if admin.db.in_transaction:
                raise SecureStartupError('PENDING_SQLITE_TRANSACTION')
            if admin.db.execute('PRAGMA integrity_check').fetchone() != ('ok',):
                raise SecureStartupError('SQLITE_INTEGRITY_FAILURE')
            admin.verify()
            admin.gate.verify_audit()
            admin.gate.registry.verify()
            events=admin.verify()
            return {'status':'SECURE_STARTUP_VERIFIED', 'dual_control_events':len(events),
                    'legacy_exposure_declared':False,'direct_database_exposure_declared':False,
                    'execution_authorized':False,'cutover_authorized':False}
