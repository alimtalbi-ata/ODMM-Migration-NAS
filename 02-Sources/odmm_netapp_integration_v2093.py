"""Read-only, authenticated NetApp composition with LIF evidence. Author: Abdelhalim Talbi."""
from odmm_operations_app import create_netapp_full_operations_app
from odmm_operations_security import make_request_authorizer
from odmm_trust_v2091 import assess_lif_failover

def create_netapp_qualified_operations_app(*,registry_path,resolve_verified_principal,get_netapp_inventories,get_netapp_differences,get_lif_evidence):
    if not all(callable(v) for v in (resolve_verified_principal,get_netapp_inventories,get_netapp_differences,get_lif_evidence)):
        raise ValueError('VERIFIED_PROVIDERS_REQUIRED')
    from fastapi import Request,HTTPException
    from fastapi.responses import JSONResponse,HTMLResponse
    from html import escape
    app=create_netapp_full_operations_app(registry_path=registry_path,resolve_verified_principal=resolve_verified_principal,get_netapp_inventories=get_netapp_inventories,get_netapp_differences=get_netapp_differences)
    authorize=make_request_authorizer(resolve_verified_principal)
    async def assessment(request:Request):
        try:
            if authorize(request) is not True: raise HTTPException(403,'FORBIDDEN')
        except HTTPException: raise
        except Exception: raise HTTPException(403,'FORBIDDEN')
        try:
            data=get_lif_evidence()
            if not isinstance(data,dict) or set(data)!={'source','target'}: raise ValueError('LIF_SCHEMA')
            return assess_lif_failover(data['source'],data['target'])
        except Exception: raise HTTPException(503,'LIF_EVIDENCE_UNAVAILABLE')
    async def api(request:Request):
        return JSONResponse(await assessment(request),headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    async def page(request:Request):
        result=await assessment(request)
        items=''.join('<li>'+escape(x,quote=True)+'</li>' for x in result['blockers'])
        html='<html lang="fr"><meta charset="utf-8"><title>ODMM LIF</title><main><h1>NetApp — continuité LIF</h1><strong>BASCULE INTERDITE</strong><p>Paires : '+str(result['lif_pairs'])+'</p><ul>'+items+'</ul></main></html>'
        return HTMLResponse(html,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none';frame-ancestors 'none';base-uri 'none'"})
    app.add_api_route('/api/v1/operations/netapp/lif',api,methods=['GET'])
    app.add_api_route('/operations/netapp/lif',page,methods=['GET'],include_in_schema=False)
    return app
