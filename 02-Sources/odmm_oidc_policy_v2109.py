"""ODMM V210.9: OIDC deny-list, role policy, and fail-closed outage behavior.
Author: Abdelhalim Talbi. Read-only Operations; no cutover authorization.
"""
import re
import jwt
from odmm_oidc_boundary_v2107 import OIDCVerifier, OIDCConfigurationError
from odmm_operations_security import ROLE_PERMISSIONS

class PolicyOIDCVerifier(OIDCVerifier):
    """Extends signature/claims validation with bounded revocation and role policy.

    revocation_check(jti, subject) must return exactly False to allow. Any error
    or unknown result denies access; no implicit offline bypass.
    """
    def __init__(self, *, allowed_roles=None, revocation_check=None, require_jti=True, **kwargs):
        super().__init__(**kwargs)
        if allowed_roles is None:
            allowed_roles=frozenset(ROLE_PERMISSIONS)
        if not isinstance(allowed_roles,(frozenset,set,tuple,list)) or not allowed_roles or any(not isinstance(x,str) or x not in ROLE_PERMISSIONS for x in allowed_roles):
            raise OIDCConfigurationError('INVALID_ALLOWED_ROLES')
        if revocation_check is not None and not callable(revocation_check):
            raise OIDCConfigurationError('INVALID_REVOCATION_CHECK')
        if type(require_jti) is not bool: raise OIDCConfigurationError('INVALID_REQUIRE_JTI')
        self.allowed_roles=frozenset(allowed_roles)
        self.revocation_check=revocation_check
        self.require_jti=require_jti

    def verify(self, token):
        try:
            principal=super().verify(token)
            # Claims are only read after cryptographic verification above.
            claims=jwt.decode(token,options={'verify_signature':False,'verify_exp':False,'verify_aud':False})
            if not principal.roles <= self.allowed_roles: raise ValueError()
            jti=claims.get('jti')
            if self.require_jti or self.revocation_check is not None:
                if not isinstance(jti,str) or not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',jti): raise ValueError()
            if self.revocation_check is not None and self.revocation_check(jti,principal.subject) is not False:
                raise ValueError()
            return principal
        except Exception:
            raise PermissionError('OIDC_IDENTITY_REJECTED') from None


def create_policy_oidc_vault_operations_app(*, issuer, audience, jwks_provider,
                                             ha_client, allowed_roles=None,
                                             revocation_check=None, require_jti=True, **kwargs):
    from odmm_vault_prometheus_v2105 import create_vault_prometheus_operations_app
    verifier=PolicyOIDCVerifier(issuer=issuer,audience=audience,jwks_provider=jwks_provider,
        allowed_roles=allowed_roles,revocation_check=revocation_check,require_jti=require_jti)
    return create_vault_prometheus_operations_app(ha_client=ha_client,
        resolve_verified_principal=verifier.resolve_request,**kwargs)
