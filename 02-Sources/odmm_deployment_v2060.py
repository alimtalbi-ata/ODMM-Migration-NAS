"""Single guarded ODMM qualification deployment. Auteur: Abdelhalim Talbi."""
from odmm_secure_integration_v2059 import attach_hardened_collection
from odmm_cockpit_collection_v2060 import attach_collection_cockpit

LEGACY_PATHS = frozenset({'/api/v1/qualification/collect','/api/v1/qualification/collect-secure'})

def attach_qualification(app, *, authorize, gate, identity_provider, session_provider, csrf_secret, expected_origin, token_provider, allow_hosts, collector=None):
    """Fail closed if legacy routes or conflicting cockpit routes exist; attach both endpoints."""
    paths = {getattr(r,'path',None) for r in app.routes}
    if paths & (LEGACY_PATHS | {'/qualification/cockpit','/api/v1/qualification/collect-hardened'}):
        raise ValueError('QUALIFICATION_ROUTE_CONFLICT')
    if not callable(authorize):
        raise ValueError('AUTHORIZATION_REQUIRED')
    # Validate collection dependencies first; ensure UI route is added only on success.
    attach_hardened_collection(app, gate=gate, identity_provider=identity_provider,
       session_provider=session_provider, csrf_secret=csrf_secret,
       expected_origin=expected_origin, token_provider=token_provider,
       allow_hosts=allow_hosts, collector=collector)
    attach_collection_cockpit(app, authorize=authorize)
    return app
