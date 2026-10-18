"""Pinned-JWKS OIDC boundary for isolated qualification review. Author: Abdelhalim Talbi.

Only access tokens from a trusted issuer are accepted. JWKS is provisioned offline;
no token-controlled key retrieval or implicit refresh is permitted.
"""
from fastapi import HTTPException
from odmm_oidc_verifier import OIDCVerifier
from qualification_production_app_v2236 import create_production_review_app

REVIEW_ROLES = frozenset({'qualification:read','qualification:write','qualification:approve','qualification:prepare'})


def oidc_authenticator(*, issuer, audience, jwks, role_claim='roles', clock=None, rotation=None):
    verifier = rotation if rotation is not None else OIDCVerifier(issuer=issuer, audience=audience, jwks=jwks,
                            role_claim=role_claim, allowed_roles=REVIEW_ROLES, clock=clock)
    def authenticate(request):
        try:
            principal = verifier.resolve_request(request)
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail='INVALID_ACCESS_TOKEN',
                                headers={'WWW-Authenticate': 'Bearer'}) from exc
        return {'subject': principal.subject, 'roles': list(principal.roles)}
    return authenticate


def create_oidc_production_review_app(*, issuer, audience, jwks, role_claim='roles', clock=None, rotation=None, **kwargs):
    if 'authenticate' in kwargs:
        raise ValueError('PRODUCTION_AUTHENTICATOR_OVERRIDE_FORBIDDEN')
    authenticate = oidc_authenticator(issuer=issuer, audience=audience, jwks=jwks,
                                     role_claim=role_claim, clock=clock, rotation=rotation)
    return create_production_review_app(authenticate=authenticate, **kwargs)
