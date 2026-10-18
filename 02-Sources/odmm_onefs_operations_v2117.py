"""OneFS/ONTAP Operations read-only comparison, fail closed. Author: Abdelhalim Talbi."""
from collections.abc import Mapping
from odmm_onefs_discovery_v2116 import discover_onefs, compare_onefs_ontap

DIRECTIONS = ('ONEFS_TO_NETAPP', 'NETAPP_TO_ONEFS')


def qualify_onefs_api(fetch, *, version, approved_versions):
    """Explicit site-qualified version allowlist; never auto-guess API compatibility."""
    if not callable(fetch) or not isinstance(approved_versions, (tuple, frozenset, list)):
        raise ValueError('TRUSTED_ONEFS_CAPABILITY_REQUIRED')
    if version != 'v16' or version not in approved_versions:
        raise ValueError('ONEFS_API_VERSION_NOT_QUALIFIED')
    return version


def attach_onefs_ontap_operations(app, *, authorize, get_ontap_inventory, onefs_fetch,
                                  access_zone, path, api_version='v16', approved_versions=()):
    """Providers are trusted server-side; routes never take inventory or tokens from callers."""
    if not all(callable(x) for x in (authorize, get_ontap_inventory, onefs_fetch)):
        raise ValueError('TRUSTED_PROVIDERS_REQUIRED')
    from fastapi import Request
    from fastapi.responses import JSONResponse

    @app.get('/api/v1/operations/onefs-ontap/compare/{direction}')
    def compare(request: Request, direction: str):
        headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}
        try:
            permitted = authorize(request) is True
        except Exception:
            permitted = False
        if not permitted:
            return JSONResponse({'error': 'ACCESS_DENIED'}, status_code=403, headers=headers)
        if direction not in DIRECTIONS:
            return JSONResponse({'error': 'UNSUPPORTED_DIRECTION'}, status_code=400, headers=headers)
        try:
            qualify_onefs_api(onefs_fetch, version=api_version, approved_versions=approved_versions)
            ontap = get_ontap_inventory()
            if not isinstance(ontap, Mapping):
                raise ValueError('INVALID_ONTAP_INVENTORY')
            onefs = discover_onefs(onefs_fetch, access_zone=access_zone, path=path, api_version=api_version)
            result = compare_onefs_ontap(ontap, onefs, direction=direction)
        except Exception:
            return JSONResponse({'error': 'EVIDENCE_UNAVAILABLE', 'cutover_authorized': False},
                                status_code=503, headers=headers)
        return JSONResponse(result, headers=headers)
    return app


def create_onefs_ontap_operations_app(*, registry_path, resolve_verified_principal,
                                      get_ontap_inventory, onefs_fetch, access_zone, path,
                                      api_version='v16', approved_versions=()):
    from odmm_operations_app import create_operations_app
    from odmm_operations_security import make_request_authorizer
    app = create_operations_app(registry_path=registry_path,
                                resolve_verified_principal=resolve_verified_principal)
    return attach_onefs_ontap_operations(
        app, authorize=make_request_authorizer(resolve_verified_principal),
        get_ontap_inventory=get_ontap_inventory, onefs_fetch=onefs_fetch,
        access_zone=access_zone, path=path, api_version=api_version,
        approved_versions=approved_versions)
