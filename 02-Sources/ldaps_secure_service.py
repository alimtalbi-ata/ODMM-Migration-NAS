"""Explicit fail-closed service boundary for sensitive OIDC role operations.

The facade exposes ONLY dual-control role administration. Legacy methods are
not forwarded. Deployments must not expose underlying objects to untrusted
callers: this is not monkey-patching or a global interception layer.
"""
import threading
from pathlib import Path
from contextlib import nullcontext
from ldaps_service_concurrency import InterprocessServiceGate
from ldaps_dual_control_admin import DualControlRoleAdministration
from ldaps_transition_reconciliation import TransitionReconciliationError

class SecureRoleService:
    __slots__=("__admin", "__lock", "__gate", "__strict")
    def __init__(self, dual_admin, *, gate_path=None, strict=False):
        if not isinstance(dual_admin, DualControlRoleAdministration):
            raise TransitionReconciliationError("DUAL_CONTROL_REQUIRED")
        if type(strict) is not bool:
            raise TransitionReconciliationError("INVALID_STRICT_MODE")
        if strict and gate_path is None:
            raise TransitionReconciliationError("STRICT_SERVICE_GATE_REQUIRED")
        self.__strict=strict
        self.__admin=dual_admin
        self.__lock=threading.RLock()
        self.__gate=InterprocessServiceGate(gate_path) if gate_path is not None else None

    def set_role(self, *, security_token, operations_token, target_subject, role, enabled, now):
        with self.__lock, (self.__gate.exclusive() if self.__gate else nullcontext()):
            if self.__strict:
                self.__admin.verify()
                self.__admin.gate.verify_audit()
                self.__admin.gate.registry.verify()
            result=self.__admin.set_grant(
                security_token=security_token,operations_token=operations_token,
                target_subject=target_subject,role=role,enabled=enabled,now=now)
            return {**result,"service_boundary":"DUAL_CONTROL_ONLY",
                    "execution_authorized":False,"cutover_authorized":False}

    def audit_status(self):
        with self.__lock, (self.__gate.exclusive() if self.__gate else nullcontext()):
            if self.__strict:
                self.__admin.gate.verify_audit()
                self.__admin.gate.registry.verify()
            rows=self.__admin.verify()
            return {"valid":True,"events":len(rows),"execution_authorized":False,
                    "cutover_authorized":False}

    def __getattr__(self, name):
        raise AttributeError("SERVICE_METHOD_NOT_EXPOSED")
