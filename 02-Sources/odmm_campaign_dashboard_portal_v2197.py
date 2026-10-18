"""Authenticated read-only campaign dashboard routes. Author: Abdelhalim Talbi."""
from pathlib import Path
from odmm_campaign_dashboard_v2196 import build_dashboard
from odmm_campaign_dashboard_ui_v2198 import render_hardened, csp_policy

def attach_campaign_dashboard(app, *, authorize, audit_path, anchor_path):
    if not callable(authorize):
        raise ValueError('AUTHORIZATION_PROVIDER_REQUIRED')
    if not hasattr(app, 'add_api_route'):
        raise ValueError('FASTAPI_APP_REQUIRED')
    from fastapi import HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    from odmm_access_audit_v2184 import AuditError
    audit_path, anchor_path = Path(audit_path), Path(anchor_path)
    def load(request, identity, mismatches):
        if authorize(request) is not True:
            raise HTTPException(status_code=403, detail='FORBIDDEN')
        if identity is not None and (len(identity)>256 or any(ord(c)<32 for c in identity)):
            raise HTTPException(status_code=422, detail='INVALID_IDENTITY')
        try:
            return build_dashboard(audit_path, anchor_path, identity=identity, only_mismatches=mismatches)
        except (AuditError, OSError, ValueError, Exception) as exc:
            # Fail closed without exposing local paths or database contents.
            raise HTTPException(status_code=503, detail='AUDIT_UNAVAILABLE') from exc
    async def page(request: Request, identity: str | None = None, mismatches: bool = False):
        report=load(request, identity, mismatches)
        html=render_hardened(report)
        return HTMLResponse(html, headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':csp_policy(html),'Referrer-Policy':'no-referrer','X-Frame-Options':'DENY'})
    async def export(request: Request, identity: str | None = None, mismatches: bool = False):
        return JSONResponse(load(request,identity,mismatches),headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    app.add_api_route('/operations/campaign-audit',page,methods=['GET'],include_in_schema=False)
    app.add_api_route('/api/v1/operations/campaign-audit/export',export,methods=['GET'],include_in_schema=False)
    return page
