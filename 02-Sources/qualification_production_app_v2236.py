"""Isolated production ASGI review application. Author: Abdelhalim Talbi.

Deploy this app alone, not mounted inside a legacy application. Authentication
callback MUST verify OIDC signatures, issuer, audience, expiry and token roles.
"""
from pathlib import Path
from fastapi import FastAPI
from qualification_secure_integration_v2235 import attach_production_review_portal
from qualification_review_security_v2217 import verify_anchor

_ALLOWED = {
    ('GET', '/operations/qualification-history/reviews'),
    ('GET', '/api/v1/operations/qualification-history/reviews'),
    ('POST', '/api/v1/operations/qualification-history/reviews'),
}


def create_production_review_app(*, authenticate, db_path, review_db_path,
                                 required_checks, secret, trusted_origins, anchor_path,
                                 thresholds=None):
    """Fail closed on startup; do not mount legacy or custody mutation routes."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError('PRODUCTION_SECRET_INVALID')
    if not callable(authenticate):
        raise ValueError('PRODUCTION_AUTHENTICATOR_REQUIRED')
    if not Path(db_path).is_file() or not Path(review_db_path).is_file():
        raise ValueError('PRODUCTION_DATABASE_REQUIRED')
    try:
        verify_anchor(review_db_path, anchor_path, secret)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError('PRODUCTION_ANCHOR_UNVERIFIED') from exc
    app = FastAPI(title='ODMM qualification review (isolated)', docs_url=None,
                  redoc_url=None, openapi_url=None)
    attach_production_review_portal(app, authenticate=authenticate, db_path=db_path,
        review_db_path=review_db_path, required_checks=required_checks,
        secret=secret, trusted_origins=trusted_origins, anchor_path=anchor_path,
        thresholds=thresholds)
    actual = {(method, route.path) for route in app.routes
              for method in (getattr(route, 'methods', None) or ())}
    if actual != _ALLOWED:
        raise ValueError('PRODUCTION_ROUTE_INVENTORY_MISMATCH')
    app.state.odmm_production_review_isolated = True
    return app


def assert_production_route_inventory(app):
    actual = {(method, route.path) for route in app.routes
              for method in (getattr(route, 'methods', None) or ())}
    if actual != _ALLOWED:
        raise ValueError('PRODUCTION_ROUTE_INVENTORY_MISMATCH')
    return True
