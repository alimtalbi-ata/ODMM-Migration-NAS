"""V197.3 fail-closed HTTP bearer entrypoint, no interactive login flow.

Requires a deployment-pinned JWKS file and TLS termination at a trusted proxy.
This module never fetches token-supplied URLs or grants roles from headers.
"""
import json
import os
from pathlib import Path
from odmm_oidc_hot_reload import ReloadingOIDCVerifier
from odmm_production_entrypoint import create_production_app


def create_oidc_app(*, registry_path, grants_path, issuer, audience, jwks_path):
    path=Path(jwks_path)
    if path.is_symlink():
        raise ValueError('JWKS_FILE_INVALID')
    if not path.is_file():
        raise FileNotFoundError(path)
    # Preserve the public startup error contract while runtime reloads fail closed.
    initial=json.loads(path.read_text(encoding='utf-8'))
    from odmm_oidc_verifier import OIDCVerifier
    OIDCVerifier(issuer=issuer,audience=audience,jwks=initial)
    verifier=ReloadingOIDCVerifier(issuer=issuer,audience=audience,jwks_path=path,
                                   check_interval=float(os.environ.get("ODMM_JWKS_CHECK_INTERVAL", "0")))
    app=create_production_app(registry_path=registry_path,grants_path=grants_path,
                              resolve_verified_principal=verifier.resolve_request)
    app.state.oidc_issuer=issuer
    return app


def create_from_environment():
    required=('ODMM_REGISTRY_DB','ODMM_GRANTS_DB','ODMM_OIDC_ISSUER',
              'ODMM_OIDC_AUDIENCE','ODMM_OIDC_JWKS_PATH')
    missing=[name for name in required if not os.environ.get(name)]
    if missing: raise RuntimeError('MISSING_REQUIRED_CONFIGURATION:'+','.join(missing))
    return create_oidc_app(registry_path=os.environ['ODMM_REGISTRY_DB'],
                           grants_path=os.environ['ODMM_GRANTS_DB'],
                           issuer=os.environ['ODMM_OIDC_ISSUER'],
                           audience=os.environ['ODMM_OIDC_AUDIENCE'],
                           jwks_path=os.environ['ODMM_OIDC_JWKS_PATH'])
