"""Portable signed campaign history anchors and deterministic version diffs.
HMAC is symmetric: verification requires a trusted out-of-band key and a separately
retained anchor to detect truncation/rollback. Author: Abdelhalim Talbi.
"""
import hashlib
import hmac
import json
import re
from odmm_campaign_history_v2096 import canonical
from odmm_campaign_v2095 import verify_campaign

_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

def _secret(resolver, key_id):
    if not callable(resolver) or not isinstance(key_id,str) or not _ID.fullmatch(key_id):
        raise ValueError('INVALID_SIGNER')
    secret=resolver(key_id)
    if not isinstance(secret,bytes) or len(secret)<32:
        raise ValueError('SIGNER_UNAVAILABLE')
    return secret

def _history_rows(history,campaign_id):
    timeline=history.timeline(campaign_id)
    if not timeline['events']:
        raise ValueError('EMPTY_HISTORY')
    return timeline

def create_anchor(history,campaign_id,*,key_id,resolver):
    key=_secret(resolver,key_id)
    timeline=_history_rows(history,campaign_id)
    record={'schema':'odmm.campaign.anchor.v2097','campaign_id':campaign_id,
            'version':timeline['version'],'head_hash':timeline['head_hash'],
            'key_id':key_id,'algorithm':'HMAC-SHA256','cutover_authorized':False}
    record['mac']=hmac.new(key,canonical(record),hashlib.sha256).hexdigest()
    return record

def verify_anchor(history,anchor,*,resolver):
    if not isinstance(anchor,dict) or set(anchor)!={'schema','campaign_id','version','head_hash','key_id','algorithm','cutover_authorized','mac'}:
        raise ValueError('INVALID_ANCHOR')
    if anchor['schema']!='odmm.campaign.anchor.v2097' or anchor['algorithm']!='HMAC-SHA256' or anchor['cutover_authorized'] is not False:
        raise ValueError('INVALID_ANCHOR')
    key=_secret(resolver,anchor['key_id'])
    expected=hmac.new(key,canonical({k:v for k,v in anchor.items() if k!='mac'}),hashlib.sha256).hexdigest()
    if not isinstance(anchor['mac'],str) or not hmac.compare_digest(expected,anchor['mac']):
        raise ValueError('INVALID_ANCHOR_MAC')
    timeline=_history_rows(history,anchor['campaign_id'])
    if type(anchor['version']) is not int or timeline['version']!=anchor['version'] or not hmac.compare_digest(timeline['head_hash'],str(anchor['head_hash'])):
        raise ValueError('HISTORY_ANCHOR_MISMATCH')
    return {'verified':True,'campaign_id':anchor['campaign_id'],'version':timeline['version'],
            'status':'BLOCKED','cutover_authorized':False}

def export_verified_history(history,campaign_id,*,key_id,resolver):
    anchor=create_anchor(history,campaign_id,key_id=key_id,resolver=resolver)
    timeline=history.timeline(campaign_id)
    return {'schema':'odmm.campaign.audit.export.v2097','anchor':anchor,'timeline':timeline,
            'limitations':['HMAC_SHARED_SECRET','ANCHOR_MUST_BE_STORED_EXTERNALLY','NO_CUTOVER_APPROVAL']}

def compare_versions(history,campaign_id,old_version,new_version):
    if type(old_version) is not int or type(new_version) is not int or old_version<1 or new_version<=old_version:
        raise ValueError('INVALID_VERSION_RANGE')
    timeline=history.timeline(campaign_id)
    if new_version>timeline['version']:raise ValueError('VERSION_NOT_FOUND')
    a=timeline['events'][old_version-1];b=timeline['events'][new_version-1]
    return {'schema':'odmm.campaign.diff.v2097','campaign_id':campaign_id,
            'from_version':old_version,'to_version':new_version,
            'report_count_delta':b['report_count']-a['report_count'],
            'blockers_added':sorted(set(b['blockers'])-set(a['blockers'])),
            'blockers_removed':sorted(set(a['blockers'])-set(b['blockers'])),
            'from_digest':a['digest'],'to_digest':b['digest'],
            'status':'BLOCKED','cutover_authorized':False}

def create_anchor_operations_app(*,history_path,registry_path,resolve_verified_principal,get_netapp_inventories,get_netapp_differences,get_lif_evidence,get_campaign_reports):
    """Read-only diff API and HTML, without exposing HMAC signing keys via HTTP."""
    from fastapi import Request,HTTPException
    from fastapi.responses import JSONResponse,HTMLResponse
    from html import escape
    from odmm_campaign_history_v2096 import create_history_operations_app,CampaignHistory
    from odmm_operations_security import make_request_authorizer
    app=create_history_operations_app(history_path=history_path,registry_path=registry_path,resolve_verified_principal=resolve_verified_principal,get_netapp_inventories=get_netapp_inventories,get_netapp_differences=get_netapp_differences,get_lif_evidence=get_lif_evidence,get_campaign_reports=get_campaign_reports)
    authorize=make_request_authorizer(resolve_verified_principal)
    history=CampaignHistory(history_path)
    async def get(request:Request,campaign_id:str,old_version:int,new_version:int):
        try:
            if authorize(request) is not True:raise HTTPException(403,'FORBIDDEN')
        except HTTPException:raise
        except Exception:raise HTTPException(403,'FORBIDDEN')
        try:return compare_versions(history,campaign_id,old_version,new_version)
        except ValueError as exc:
            if str(exc) in ('INVALID_VERSION_RANGE','VERSION_NOT_FOUND','CAMPAIGN_INVALID'):raise HTTPException(400,str(exc))
            raise HTTPException(503,'HISTORY_INTEGRITY_FAILURE')
        except Exception:raise HTTPException(503,'HISTORY_UNAVAILABLE')
    async def api(request:Request,campaign_id:str,old_version:int,new_version:int):
        return JSONResponse(await get(request,campaign_id,old_version,new_version),headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    async def page(request:Request,campaign_id:str,old_version:int,new_version:int):
        d=await get(request,campaign_id,old_version,new_version)
        html='<html lang="fr"><meta charset="utf-8"><title>ODMM Diff</title><main><h1>Campagne '+escape(campaign_id,quote=True)+'</h1><strong>BASCULE BLOQUÉE</strong><p>Versions '+str(old_version)+' → '+str(new_version)+'</p><p>Variation rapports : '+str(d['report_count_delta'])+'</p><h2>Nouveaux blocages</h2><ul>'+''.join('<li>'+escape(str(x),quote=True)+'</li>' for x in d['blockers_added'])+'</ul><h2>Blocages disparus</h2><ul>'+''.join('<li>'+escape(str(x),quote=True)+'</li>' for x in d['blockers_removed'])+'</ul></main></html>'
        return HTMLResponse(html,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none';frame-ancestors 'none';base-uri 'none'"})
    route='/api/v1/operations/netapp/campaigns/{campaign_id}/diff/{old_version}/{new_version}'
    app.add_api_route(route,api,methods=['GET'])
    app.add_api_route('/operations/netapp/campaigns/{campaign_id}/diff/{old_version}/{new_version}',page,methods=['GET'],include_in_schema=False)
    return app
