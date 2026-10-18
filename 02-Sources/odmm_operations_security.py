"""Fail-closed shared principal/role boundary for read-only ODMM operations.

Identity verification belongs to the hosting OIDC/session middleware. The
resolver must return a verified principal, not untrusted request headers.
"""
from dataclasses import dataclass
from typing import FrozenSet

READ_PERMISSIONS = frozenset({'operations:read', 'audit:read'})
ROLE_PERMISSIONS = {
    'viewer': frozenset({'operations:read'}),
    'auditor': frozenset({'operations:read', 'audit:read'}),
    'operator': frozenset({'operations:read'}),
    'admin': READ_PERMISSIONS,
}

@dataclass(frozen=True)
class Principal:
    subject: str
    roles: FrozenSet[str]
    verified: bool = False


def require_permission(principal, permission):
    if permission not in READ_PERMISSIONS:
        raise PermissionError('PERMISSION_NOT_SUPPORTED')
    if not isinstance(principal, Principal) or not principal.verified:
        raise PermissionError('VERIFIED_IDENTITY_REQUIRED')
    if not isinstance(principal.subject, str) or not principal.subject.strip() or len(principal.subject) > 256:
        raise PermissionError('SUBJECT_INVALID')
    if not isinstance(principal.roles, frozenset) or not principal.roles or not principal.roles <= ROLE_PERMISSIONS.keys():
        raise PermissionError('ROLE_INVALID')
    allowed = frozenset().union(*(ROLE_PERMISSIONS[r] for r in principal.roles))
    if permission not in allowed:
        raise PermissionError('FORBIDDEN')
    return principal


def make_request_authorizer(resolve_verified_principal, *, permission='operations:read'):
    if not callable(resolve_verified_principal):
        raise ValueError('VERIFIED_PRINCIPAL_RESOLVER_REQUIRED')
    if permission not in READ_PERMISSIONS:
        raise ValueError('PERMISSION_NOT_SUPPORTED')
    def authorize(request):
        try:
            require_permission(resolve_verified_principal(request), permission)
        except (PermissionError, ValueError, TypeError, KeyError):
            return False
        return True
    return authorize
