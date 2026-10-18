"""Fail-closed session binding for qualification endpoints. Auteur: Abdelhalim Talbi."""
from fastapi import HTTPException
from odmm_session_registry_v2062 import SessionRegistry
from odmm_deployment_v2060 import attach_qualification

COOKIE = 'odmm_session'


def attach_session_qualification(app, *, registry, gate, csrf_secret, expected_origin,
                                 token_provider, allow_hosts, collector=None):
    """Bind identity, session and UI authorization to the SAME registry lookup.

    Deployment must issue Secure/HttpOnly/SameSite cookies and a CSRF cookie via
    its HTTPS login handler. This module never accepts identity from headers.
    """
    if not isinstance(registry, SessionRegistry):
        raise ValueError('REGISTRY_REQUIRED')

    def resolve(request):
        token = request.cookies.get(COOKIE, '')
        principal = registry.resolve(token)
        if principal is None:
            raise HTTPException(status_code=401, detail='SESSION_INVALID')
        return token, principal

    def identity_provider(request):
        _, principal = resolve(request)
        return principal['actor'], principal['role']

    def session_provider(request):
        token, _ = resolve(request)
        return token

    def authorize(request):
        try:
            _, principal = resolve(request)
            return principal['role'] in ('viewer', 'operator', 'admin')
        except HTTPException:
            return False

    return attach_qualification(app, authorize=authorize, gate=gate,
                                identity_provider=identity_provider,
                                session_provider=session_provider,
                                csrf_secret=csrf_secret, expected_origin=expected_origin,
                                token_provider=token_provider, allow_hosts=allow_hosts,
                                collector=collector)
