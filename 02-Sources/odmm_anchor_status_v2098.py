"""Fail-closed campaign anchor health and read-only Operations integration.
Author: Abdelhalim Talbi. External anchor and secret must be independently supplied.
"""
from html import escape
from odmm_campaign_anchor_v2097 import verify_anchor,create_anchor_operations_app
from odmm_campaign_history_v2096 import CampaignHistory

def assess_anchor_status(history, campaign_id, *, anchor_provider, resolver):
    result={'schema':'odmm.campaign.anchor.health.v2098','campaign_id':campaign_id,
            'integrity':'UNVERIFIED','status':'BLOCKED','cutover_authorized':False,
            'key_id':None,'version':None,'reason':'ANCHOR_UNAVAILABLE'}
    try:
        if not callable(anchor_provider): raise ValueError('ANCHOR_UNAVAILABLE')
        anchor=anchor_provider(campaign_id)
        if not isinstance(anchor,dict) or anchor.get('campaign_id')!=campaign_id:
            raise ValueError('ANCHOR_MISMATCH')
        verified=verify_anchor(history,anchor,resolver=resolver)
        result.update(integrity='VERIFIED',reason='HMAC_AND_HISTORY_MATCH',
                      key_id=anchor['key_id'],version=verified['version'])
    except Exception as exc:
        code=str(exc)
        result['reason']=code if code in {'ANCHOR_UNAVAILABLE','ANCHOR_MISMATCH','SIGNER_UNAVAILABLE',
          'INVALID_ANCHOR','INVALID_ANCHOR_MAC','HISTORY_ANCHOR_MISMATCH','HISTORY_INTEGRITY_FAILURE',
          'EMPTY_HISTORY','CAMPAIGN_INVALID','INVALID_SIGNER'} else 'ANCHOR_VERIFICATION_FAILED'
    return result

def create_anchor_status_operations_app(*,history_path,registry_path,resolve_verified_principal,
    get_netapp_inventories,get_netapp_differences,get_lif_evidence,get_campaign_reports,
    anchor_provider,secret_resolver):
    from fastapi import Request,HTTPException
    from fastapi.responses import JSONResponse,HTMLResponse
    from odmm_operations_security import make_request_authorizer
    app=create_anchor_operations_app(history_path=history_path,registry_path=registry_path,
        resolve_verified_principal=resolve_verified_principal,get_netapp_inventories=get_netapp_inventories,
        get_netapp_differences=get_netapp_differences,get_lif_evidence=get_lif_evidence,
        get_campaign_reports=get_campaign_reports)
    authorize=make_request_authorizer(resolve_verified_principal)
    history=CampaignHistory(history_path)
    async def status(request:Request,campaign_id:str):
        try:
            if authorize(request) is not True:raise HTTPException(403,'FORBIDDEN')
        except HTTPException:raise
        except Exception:raise HTTPException(403,'FORBIDDEN')
        return assess_anchor_status(history,campaign_id,anchor_provider=anchor_provider,resolver=secret_resolver)
    async def api(request:Request,campaign_id:str):
        return JSONResponse(await status(request,campaign_id),headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    async def page(request:Request,campaign_id:str):
        data=await status(request,campaign_id)
        body='<html lang="fr"><meta charset="utf-8"><title>ODMM Intégrité</title><main><h1>Intégrité campagne '+escape(campaign_id,quote=True)+'</h1><strong>BASCULE BLOQUÉE</strong><p>Vérification : '+escape(data['integrity'])+'</p><p>Motif : '+escape(data['reason'])+'</p><p>Version : '+escape(str(data['version']))+'</p></main></html>'
        return HTMLResponse(body,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
          'Content-Security-Policy':"default-src 'none';frame-ancestors 'none';base-uri 'none'"})
    app.add_api_route('/api/v1/operations/netapp/campaigns/{campaign_id}/anchor-health',api,methods=['GET'])
    app.add_api_route('/operations/netapp/campaigns/{campaign_id}/anchor-health',page,methods=['GET'],include_in_schema=False)
    return app
