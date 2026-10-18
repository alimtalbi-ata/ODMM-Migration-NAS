"""V197.2 approved deployment entrypoint: scoped-only, no legacy routes.

Does not prevent an operator from importing legacy modules in another process.
"""
from odmm_scoped_app import create_scoped_app

def create_production_app(*, registry_path, grants_path, resolve_verified_principal):
    if not callable(resolve_verified_principal): raise ValueError('VERIFIED_PRINCIPAL_RESOLVER_REQUIRED')
    app=create_scoped_app(registry_path=registry_path,grants_path=grants_path,resolve_verified_principal=resolve_verified_principal)
    expected={'/openapi.json','/docs','/docs/oauth2-redirect','/redoc','/operations',
              '/api/v1/operations/overview','/api/v1/operations/jobs',
              '/api/v1/operations/jobs/{job_id}/operations'}
    actual={r.path for r in app.routes}
    if actual != expected: raise RuntimeError('UNEXPECTED_ROUTE_SET')
    return app
