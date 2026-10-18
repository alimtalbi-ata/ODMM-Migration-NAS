"""Read-only NAS migration comparison endpoints. Author: Abdelhalim Talbi.

Server-side evidence providers only. Never accepts inventory from HTTP clients.
"""
from collections.abc import Mapping
from html import escape
from odmm_flashblade_protocol_v2114 import build_readonly_report

DIRECTIONS = ('NETAPP_TO_FLASHBLADE', 'FLASHBLADE_TO_NETAPP')

def _authorized(authorize, request):
    try:
        return authorize(request) is True
    except Exception:
        return False

def attach_nas_migration_comparison(app, *, authorize, get_ontap_inventory, get_flashblade_inventory):
    if not all(callable(f) for f in (authorize, get_ontap_inventory, get_flashblade_inventory)):
        raise ValueError('TRUSTED_AUTHORIZER_AND_INVENTORY_PROVIDERS_REQUIRED')
    from fastapi import Request
    from fastapi.responses import JSONResponse, HTMLResponse

    def report(request, direction):
        if not _authorized(authorize, request):
            return JSONResponse({'error':'ACCESS_DENIED'}, status_code=403, headers={'Cache-Control':'no-store'})
        if direction not in DIRECTIONS:
            return JSONResponse({'error':'UNSUPPORTED_DIRECTION'}, status_code=400, headers={'Cache-Control':'no-store'})
        try:
            ontap, blade = get_ontap_inventory(), get_flashblade_inventory()
            if not isinstance(ontap, Mapping) or not isinstance(blade, Mapping):
                raise ValueError('INVENTORY_INVALID')
            result = build_readonly_report(ontap, blade, direction=direction)
        except Exception:
            return JSONResponse({'error':'EVIDENCE_UNAVAILABLE','cutover_authorized':False}, status_code=503, headers={'Cache-Control':'no-store'})
        return JSONResponse(result, headers={'Cache-Control':'no-store'})

    @app.get('/api/v1/operations/nas-migration/compare/{direction}', include_in_schema=True)
    def compare(request: Request, direction: str):
        return report(request, direction)

    @app.get('/operations/nas-migration', include_in_schema=True)
    def portal(request: Request):
        if not _authorized(authorize, request):
            return HTMLResponse('Access denied', status_code=403, headers={'Cache-Control':'no-store'})
        rows=[]
        for direction in DIRECTIONS:
            response=report(request,direction)
            if response.status_code != 200:
                rows.append(f'<tr><td>{escape(direction)}</td><td>Evidence unavailable</td><td>BLOCKED</td></tr>')
                continue
            import json
            data=json.loads(response.body)
            mismatches=sum(len(data[p]['blockers']) for p in ('nfs','smb'))
            rows.append(f'<tr><td>{escape(direction)}</td><td>{mismatches} blocking checks</td><td>BLOCKED</td></tr>')
        page='<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ODMM NAS Migration</title></head><body><main><h1>NAS migration qualification</h1><p>Read-only; cutover never authorized by this page.</p><table><thead><tr><th>Direction</th><th>Evidence</th><th>Gate</th></tr></thead><tbody>'+''.join(rows)+'</tbody></table></main></body></html>'
        return HTMLResponse(page, headers={'Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'",'X-Content-Type-Options':'nosniff'})


def create_nas_migration_operations_app(*, registry_path, resolve_verified_principal, get_ontap_inventory, get_flashblade_inventory):
    from odmm_operations_app import create_operations_app
    from odmm_operations_security import make_request_authorizer
    app=create_operations_app(registry_path=registry_path, resolve_verified_principal=resolve_verified_principal)
    attach_nas_migration_comparison(app,authorize=make_request_authorizer(resolve_verified_principal),get_ontap_inventory=get_ontap_inventory,get_flashblade_inventory=get_flashblade_inventory)
    return app
