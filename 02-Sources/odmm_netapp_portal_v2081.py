"""Authenticated read-only NetApp preflight extension for ODMM operations.
Inventories are injected by trusted server code, never accepted from browser payloads.
Auteur: Abdelhalim Talbi.
"""
from odmm_netapp_quality_v2081 import assess_pair
from odmm_netapp_mapping_v2080 import render_mapping_html

def attach_netapp_preflight(app, *, authorize, get_inventories):
    if not callable(authorize) or not callable(get_inventories):
        raise ValueError('AUTHORIZATION_AND_INVENTORY_PROVIDER_REQUIRED')
    from fastapi import Request, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse
    async def preflight(request: Request):
        if authorize(request) is not True:
            raise HTTPException(403,'FORBIDDEN')
        try:
            source,target=get_inventories()
            result=assess_pair(source,target)
        except Exception:
            raise HTTPException(503,'NETAPP_INVENTORY_UNAVAILABLE')
        return JSONResponse(result,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    async def dashboard(request: Request):
        if authorize(request) is not True:
            raise HTTPException(403,'FORBIDDEN')
        try:
            source,target=get_inventories()
            result=assess_pair(source,target)
        except Exception:
            raise HTTPException(503,'NETAPP_INVENTORY_UNAVAILABLE')
        html=render_mapping_html(result).replace('Préqualification V208.0','Préqualification V208.1').replace('Rapport de démonstration — aucune connexion à une appliance réelle','Inventaires fournis par le serveur — état des preuves non validé')
        return HTMLResponse(html,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
           'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"})
    app.add_api_route('/api/v1/operations/netapp/preflight',preflight,methods=['GET'])
    app.add_api_route('/operations/netapp',dashboard,methods=['GET'],include_in_schema=False)
    return preflight
