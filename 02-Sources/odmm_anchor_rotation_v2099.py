"""Read-only HMAC key lifecycle policy for ODMM anchors. Author: Abdelhalim Talbi.
The policy must be supplied from an independently trusted configuration source.
"""
import re
from datetime import datetime, timezone
from odmm_anchor_status_v2098 import assess_anchor_status

_ID = re.compile(r'^[A-Za-z0-9_.-]{1,128}$')

def _instant(value):
    if not isinstance(value,str): raise ValueError('INVALID_POLICY_TIMESTAMP')
    try:
        parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
        if parsed.tzinfo is None: raise ValueError('INVALID_POLICY_TIMESTAMP')
        return parsed.astimezone(timezone.utc)
    except (TypeError,ValueError) as exc: raise ValueError('INVALID_POLICY_TIMESTAMP') from exc

def assess_rotation(history,campaign_id,*,anchor_provider,resolver,policy_provider,now=None,warning_seconds=604800):
    """Fail closed if no externally trusted policy, revoked, or expired key."""
    base=assess_anchor_status(history,campaign_id,anchor_provider=anchor_provider,resolver=resolver)
    base.update(schema='odmm.campaign.anchor.rotation.v2099',rotation='UNVERIFIED',expires_at=None,
                warning=False,cutover_authorized=False,status='BLOCKED')
    if base['integrity']!='VERIFIED':return base
    try:
        if not callable(policy_provider):raise ValueError('POLICY_UNAVAILABLE')
        policy=policy_provider(base['key_id'])
        if not isinstance(policy,dict) or set(policy)!={'key_id','not_before','not_after','state'}:
            raise ValueError('INVALID_POLICY')
        if not isinstance(policy['key_id'],str) or not _ID.fullmatch(policy['key_id']) or policy['key_id']!=base['key_id']:
            raise ValueError('KEY_POLICY_MISMATCH')
        if policy['state'] not in ('ACTIVE','REVOKED','RETIRED'):raise ValueError('INVALID_POLICY')
        start,end=_instant(policy['not_before']),_instant(policy['not_after'])
        if end<=start:raise ValueError('INVALID_POLICY')
        current=now if now is not None else datetime.now(timezone.utc)
        if not isinstance(current,datetime) or current.tzinfo is None:raise ValueError('INVALID_NOW')
        current=current.astimezone(timezone.utc)
        base['expires_at']=end.isoformat()
        if policy['state']!='ACTIVE':base.update(rotation='REVOKED',reason='KEY_NOT_ACTIVE')
        elif current<start:base.update(rotation='NOT_YET_VALID',reason='KEY_NOT_YET_VALID')
        elif current>=end:base.update(rotation='EXPIRED',reason='KEY_EXPIRED')
        else:
            remaining=(end-current).total_seconds()
            base.update(rotation='EXPIRING' if remaining<=warning_seconds else 'CURRENT',
                        warning=remaining<=warning_seconds,reason='ANCHOR_VALID_KEY_'+('EXPIRING' if remaining<=warning_seconds else 'CURRENT'))
    except Exception as exc:
        base.update(rotation='UNVERIFIED',reason=str(exc) if str(exc) in {'POLICY_UNAVAILABLE','INVALID_POLICY','KEY_POLICY_MISMATCH','INVALID_POLICY_TIMESTAMP','INVALID_NOW'} else 'POLICY_VERIFICATION_FAILED')
    return base

def create_rotation_operations_app(*,history_path,registry_path,resolve_verified_principal,
    get_netapp_inventories,get_netapp_differences,get_lif_evidence,get_campaign_reports,
    anchor_provider,secret_resolver,policy_provider):
    """Add authenticated read-only rotation health endpoints to Operations."""
    from html import escape
    from fastapi import Request,HTTPException
    from fastapi.responses import JSONResponse,HTMLResponse
    from odmm_anchor_status_v2098 import create_anchor_status_operations_app
    from odmm_campaign_history_v2096 import CampaignHistory
    from odmm_operations_security import make_request_authorizer
    app=create_anchor_status_operations_app(history_path=history_path,registry_path=registry_path,
        resolve_verified_principal=resolve_verified_principal,get_netapp_inventories=get_netapp_inventories,
        get_netapp_differences=get_netapp_differences,get_lif_evidence=get_lif_evidence,
        get_campaign_reports=get_campaign_reports,anchor_provider=anchor_provider,secret_resolver=secret_resolver)
    history=CampaignHistory(history_path)
    authorize=make_request_authorizer(resolve_verified_principal)
    async def data(request:Request,campaign_id:str):
        try:
            if authorize(request) is not True:raise HTTPException(403,'FORBIDDEN')
        except HTTPException:raise
        except Exception:raise HTTPException(403,'FORBIDDEN')
        return assess_rotation(history,campaign_id,anchor_provider=anchor_provider,resolver=secret_resolver,
                               policy_provider=policy_provider)
    async def api(request:Request,campaign_id:str):
        return JSONResponse(await data(request,campaign_id),headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    async def page(request:Request,campaign_id:str):
        result=await data(request,campaign_id)
        html='<html lang="fr"><meta charset="utf-8"><title>ODMM Rotation</title><main><h1>Rotation ancrage '+escape(campaign_id,quote=True)+'</h1><strong>Cutover bloqué</strong><p>Intégrité : '+escape(result['integrity'])+'</p><p>Rotation : '+escape(result['rotation'])+'</p><p>Motif : '+escape(result['reason'])+'</p></main></html>'
        return HTMLResponse(html,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
            'Content-Security-Policy':"default-src 'none';frame-ancestors 'none';base-uri 'none'"})
    app.add_api_route('/api/v1/operations/netapp/campaigns/{campaign_id}/anchor-rotation',api,methods=['GET'])
    app.add_api_route('/operations/netapp/campaigns/{campaign_id}/anchor-rotation',page,methods=['GET'],include_in_schema=False)
    return app
