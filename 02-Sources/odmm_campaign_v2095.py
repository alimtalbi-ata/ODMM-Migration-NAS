"""Read-only campaign qualification cockpit. Author: Abdelhalim Talbi."""
import hashlib
import hmac
import json
import re
from html import escape
from odmm_qualification_v2094 import verify_report_digest

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()

def assess_campaign(campaign_id, reports):
    if not isinstance(campaign_id,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',campaign_id):
        raise ValueError('CAMPAIGN_INVALID')
    if not isinstance(reports,list) or not reports or len(reports)>500:
        raise ValueError('REPORTS_REQUIRED_OR_LIMIT_EXCEEDED')
    seen=set(); entries=[]; blockers=[]
    for index,report in enumerate(reports):
        if not isinstance(report,dict) or report.get('campaign_id')!=campaign_id or not verify_report_digest(report):
            blockers.append('INVALID_OR_FOREIGN_REPORT'); continue
        digest=report['sha256']
        if digest in seen:
            blockers.append('DUPLICATE_REPORT');continue
        seen.add(digest)
        if report.get('cutover_authorized') is not False or report.get('status')!='BLOCKED':
            blockers.append('UNSAFE_REPORT_STATUS');continue
        entries.append({'sha256':digest,'observed_at':report.get('observed_at'),'blockers':report.get('blockers',[])})
        blockers.extend(report.get('blockers',[]))
    result={'schema':'odmm.campaign.v2095','campaign_id':campaign_id,'status':'BLOCKED','cutover_authorized':False,'report_count':len(entries),'submitted_count':len(reports),'reports':entries,'blockers':sorted(set(blockers+['INDEPENDENT_APPROVAL_REQUIRED'])),'limitations':['CALLER_SUPPLIED_REPORTS','NO_HARDWARE_ATTESTATION','NO_CUTOVER_APPROVAL']}
    result['sha256']=hashlib.sha256(_canonical(result)).hexdigest()
    return result

def verify_campaign(result):
    if not isinstance(result,dict) or not isinstance(result.get('sha256'),str):return False
    try:return hmac.compare_digest(hashlib.sha256(_canonical({k:v for k,v in result.items() if k!='sha256'})).hexdigest(),result['sha256'])
    except (ValueError,TypeError,OverflowError):return False

def create_campaign_operations_app(*,registry_path,resolve_verified_principal,get_netapp_inventories,get_netapp_differences,get_lif_evidence,get_campaign_reports):
    from fastapi import Request,HTTPException
    from fastapi.responses import JSONResponse,HTMLResponse
    from odmm_netapp_integration_v2093 import create_netapp_qualified_operations_app
    from odmm_operations_security import make_request_authorizer
    if not callable(get_campaign_reports):raise ValueError('CAMPAIGN_PROVIDER_REQUIRED')
    app=create_netapp_qualified_operations_app(registry_path=registry_path,resolve_verified_principal=resolve_verified_principal,get_netapp_inventories=get_netapp_inventories,get_netapp_differences=get_netapp_differences,get_lif_evidence=get_lif_evidence)
    authorize=make_request_authorizer(resolve_verified_principal)
    async def obtain(request:Request,campaign_id:str):
        try:
            if authorize(request) is not True:raise HTTPException(403,'FORBIDDEN')
        except HTTPException:raise
        except Exception:raise HTTPException(403,'FORBIDDEN')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',campaign_id):raise HTTPException(400,'CAMPAIGN_INVALID')
        try:return assess_campaign(campaign_id,get_campaign_reports(campaign_id))
        except Exception:raise HTTPException(503,'CAMPAIGN_EVIDENCE_UNAVAILABLE')
    async def api(request:Request,campaign_id:str):
        return JSONResponse(await obtain(request,campaign_id),headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    async def page(request:Request,campaign_id:str):
        data=await obtain(request,campaign_id)
        items=''.join('<li>'+escape(str(b),quote=True)+'</li>' for b in data['blockers'])
        html='<html lang="fr"><meta charset="utf-8"><title>ODMM Campagne</title><main><h1>Qualification '+escape(campaign_id,quote=True)+'</h1><strong>BASCULE BLOQUÉE</strong><p>Rapports vérifiés : '+str(data['report_count'])+'/'+str(data['submitted_count'])+'</p><ul>'+items+'</ul></main></html>'
        return HTMLResponse(html,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none';frame-ancestors 'none';base-uri 'none'"})
    app.add_api_route('/api/v1/operations/netapp/campaigns/{campaign_id}',api,methods=['GET'])
    app.add_api_route('/operations/netapp/campaigns/{campaign_id}',page,methods=['GET'],include_in_schema=False)
    return app
