"""V194.9: explicit, single guarded rotation endpoint binding for the main portal.

This is an integration adapter, not a deployed service. The portal must provide
its own authenticated identity, key custody and independently pinned anchors.
"""
from native_rotation_unified_gate import rotate_with_sealed_governance
from native_rotation_startup_guard import RotationAdmissionASGI
from native_rotation_live_route_gate import inspect_live_routes

_REQUIRED = frozenset({'keys','request_id','target_key_id','signed_target',
    'gateway_key','ledger_key','trusted_review_head','revocation_key','trusted_revocation_head'})


def build_rotation_endpoint(*, db, authorization, secrets_provider, audit=None, subject_provider=None, production=False):
    """Create one FastAPI-compatible async endpoint; never trust caller-supplied keys.

    authorization(request) must validate identity and permissions and return True.
    secrets_provider() must return all trusted parameters except request_id,
    target_key_id and signed_target. Both providers are supplied by deployment.
    """
    if production and (audit is None or subject_provider is None):
        raise ValueError('ROTATION_PRODUCTION_AUDIT_REQUIRED')
    if (audit is None) != (subject_provider is None):
        raise ValueError('ROTATION_AUDIT_AND_SUBJECT_REQUIRED_TOGETHER')
    if subject_provider is not None and not callable(subject_provider):
        raise ValueError('ROTATION_SUBJECT_PROVIDER_REQUIRED')
    if not callable(authorization) or not callable(secrets_provider):
        raise ValueError('ROTATION_PORTAL_PROVIDERS_REQUIRED')

    async def guarded_rotation(request):
        from fastapi import HTTPException
        body = await request.json()
        if getattr(authorization, "_odmm_body_aware", False):
            authorized = authorization(request, body)
        else:
            authorized = authorization(request)
        if authorized is not True:
            raise HTTPException(status_code=403, detail='ROTATION_NOT_AUTHORIZED')
        if not isinstance(body,dict) or set(body) != {'request_id','target_key_id','signed_target'}:
            raise HTTPException(status_code=400, detail='ROTATION_PAYLOAD_INVALID')
        trusted = secrets_provider()
        if not isinstance(trusted,dict) or set(trusted) != (_REQUIRED - set(body)):
            raise HTTPException(status_code=503, detail='ROTATION_TRUST_CONFIGURATION_INVALID')
        def effect():
            return rotate_with_sealed_governance(db,**{**trusted,**body})
        if audit is None:
            return effect()  # compatibility only: deployment must opt into audited mode
        from native_rotation_audited_execution import execute_audited_rotation
        subject = subject_provider(request)
        return execute_audited_rotation(audit=audit,request_id=body['request_id'],
            subject=subject,target_key_id=body['target_key_id'],
            authorize=lambda: True,execute=effect)

    return guarded_rotation


def bind_rotation_portal(app, *, db, authorization, secrets_provider, expected_routes_sha256, audit=None, subject_provider=None, production=False, production_policy=None):
    """Register exactly one route and wrap the complete ASGI app at its outer edge.

    Invoke after ordinary routes have been registered, then run startup lifespan.
    The route digest must come from an independent, trusted deployment manifest.
    """
    if production and (not isinstance(expected_routes_sha256,str) or len(expected_routes_sha256)!=64):
        raise ValueError('ROTATION_PRODUCTION_PIN_REQUIRED')
    if production and production_policy is None:
        raise ValueError('ROTATION_PRODUCTION_LOCKDOWN_REQUIRED')
    if not hasattr(app,'add_api_route'):
        raise ValueError('PORTAL_FASTAPI_REQUIRED')
    endpoint = build_rotation_endpoint(db=db,authorization=authorization,secrets_provider=secrets_provider,
        audit=audit,subject_provider=subject_provider,production=production)
    app.add_api_route('/api/v1/security/rotation',endpoint,methods=['POST'])
    admission = None
    if production:
        from native_rotation_production_lockdown import verify_production_routes
        if not isinstance(production_policy,dict) or set(production_policy)!={'allowed_routes','trusted_policy_sha256'}:
            raise ValueError('ROTATION_PRODUCTION_POLICY_INVALID')
        admission=lambda: verify_production_routes(app,rotation_endpoint=endpoint,
            allowed_routes=production_policy['allowed_routes'],
            trusted_policy_sha256=production_policy['trusted_policy_sha256'],
            trusted_routes_sha256=expected_routes_sha256)
    wrapper = RotationAdmissionASGI(app,allowed_endpoint=endpoint,expected_sha256=expected_routes_sha256,
        additional_admission=admission)
    return wrapper,endpoint


def preview_portal_routes(app, *, endpoint):
    """Offline fingerprint preview only: do not use this output as its own anchor."""
    return inspect_live_routes(app,allowed_endpoint=endpoint)
