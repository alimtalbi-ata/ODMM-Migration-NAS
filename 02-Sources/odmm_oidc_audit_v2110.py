"""ODMM V211.0: bounded privacy-preserving OIDC Operations audit.
Author: Abdelhalim Talbi. No token, claim, URL query, or secret logging.
"""
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from odmm_oidc_policy_v2109 import PolicyOIDCVerifier
from odmm_vault_prometheus_v2105 import create_vault_prometheus_operations_app

class OperationsAudit:
    def __init__(self, capacity=1000):
        if type(capacity) is not int or not 1 <= capacity <= 10000:
            raise ValueError('INVALID_AUDIT_CAPACITY')
        self._events=deque(maxlen=capacity)
        self._lock=Lock()

    def record(self, *, outcome, reason):
        if outcome not in ('ALLOW','DENY') or reason not in ('VERIFIED','IDENTITY_REJECTED','RESOLVER_FAILURE'):
            raise ValueError('INVALID_AUDIT_EVENT')
        event={'schema':'odmm.operations.auth.audit.v2110',
               'timestamp':datetime.now(timezone.utc).isoformat(),
               'outcome':outcome,'reason':reason}
        with self._lock:
            self._events.append(event)
        return event.copy()

    def snapshot(self):
        with self._lock:
            return [event.copy() for event in self._events]


def create_audited_oidc_operations_app(*, issuer, audience, jwks_provider, ha_client,
                                        audit, allowed_roles=None, revocation_check=None,
                                        require_jti=True, **kwargs):
    if not isinstance(audit, OperationsAudit):
        raise ValueError('OPERATIONS_AUDIT_REQUIRED')
    verifier=PolicyOIDCVerifier(issuer=issuer,audience=audience,jwks_provider=jwks_provider,
        allowed_roles=allowed_roles,revocation_check=revocation_check,require_jti=require_jti)

    def resolve(request):
        try:
            principal=verifier.resolve_request(request)
        except PermissionError:
            audit.record(outcome='DENY',reason='IDENTITY_REJECTED')
            raise
        except Exception:
            audit.record(outcome='DENY',reason='RESOLVER_FAILURE')
            raise PermissionError('OIDC_IDENTITY_REJECTED') from None
        audit.record(outcome='ALLOW',reason='VERIFIED')
        return principal

    return create_vault_prometheus_operations_app(ha_client=ha_client,
        resolve_verified_principal=resolve,**kwargs)
