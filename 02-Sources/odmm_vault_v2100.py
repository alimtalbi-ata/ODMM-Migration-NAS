"""ODMM V210.0 Vault KV-v2 read-only adapter and campaign security gate.
Author: Abdelhalim Talbi. No network or secrets are used unless injected by operator.
"""
import re
from datetime import datetime, timezone
from urllib.parse import quote
from odmm_anchor_rotation_v2099 import assess_rotation

_ID=re.compile(r'^[A-Za-z0-9_.-]{1,128}$')
_MOUNT=re.compile(r'^[A-Za-z0-9_-]{1,64}$')

class VaultUnavailable(RuntimeError):
    def __init__(self): super().__init__('VAULT_UNAVAILABLE')

class VaultKV2Resolver:
    """Read KV v2 secrets through a trusted injected HTTP client.

    client(path, headers) -> dict: HTTPS transport, TLS verification, bounded timeout,
    token acquisition/renewal and retry policy MUST be configured by the operator.
    Never log headers, response bodies, or exceptions from this client.
    """
    def __init__(self, *, client, token_provider, mount='secret', prefix='odmm/hmac'):
        if not callable(client) or not callable(token_provider): raise ValueError('INVALID_VAULT_ADAPTER')
        if not isinstance(mount,str) or not _MOUNT.fullmatch(mount): raise ValueError('INVALID_VAULT_MOUNT')
        if not isinstance(prefix,str) or not prefix or any(not _ID.fullmatch(x) for x in prefix.split('/')):
            raise ValueError('INVALID_VAULT_PREFIX')
        self._client,self._token_provider,self._mount,self._prefix=client,token_provider,mount,prefix

    def __call__(self,key_id):
        if not isinstance(key_id,str) or not _ID.fullmatch(key_id): raise ValueError('INVALID_KEY_ID')
        try:
            token=self._token_provider()
            if not isinstance(token,str) or not token.strip(): raise VaultUnavailable()
            path=f'/v1/{self._mount}/data/{self._prefix}/{quote(key_id,safe="")}'
            response=self._client(path,{'X-Vault-Token':token})
            if not isinstance(response,dict): raise VaultUnavailable()
            payload=response['data']['data']
            metadata=response['data']['metadata']
            if not isinstance(payload,dict) or not isinstance(metadata,dict) or metadata.get('destroyed') is True or metadata.get('deletion_time'):
                raise VaultUnavailable()
            value=payload.get('hmac_key_hex')
            if not isinstance(value,str) or len(value)<64 or len(value)%2 or not re.fullmatch('[0-9a-fA-F]+',value):
                raise VaultUnavailable()
            secret=bytes.fromhex(value)
            if len(secret)<32: raise VaultUnavailable()
            return secret
        except ValueError as exc:
            if str(exc)=='INVALID_KEY_ID': raise
            raise VaultUnavailable() from None
        except Exception:
            raise VaultUnavailable() from None

def assess_vault_campaign(history,campaign_id,*,anchor_provider,secret_resolver,policy_provider,vault_health,now=None,warning_seconds=604800):
    """Informational security report; NEVER authorizes cutover or changes keys."""
    result={'schema':'odmm.campaign.vault.security.v2100','campaign_id':campaign_id,
            'status':'BLOCKED','cutover_authorized':False,'vault':'UNVERIFIED',
            'integrity':'UNVERIFIED','rotation':'UNVERIFIED','alert':'SECURITY_UNVERIFIED',
            'manual_renewal_recommended':False,'reason':'SECURITY_UNVERIFIED'}
    if not isinstance(campaign_id,str) or not _ID.fullmatch(campaign_id):
        result['reason']='CAMPAIGN_INVALID';return result
    try:
        health=vault_health() if callable(vault_health) else None
        if not isinstance(health,dict) or health.get('available') is not True:
            result.update(vault='UNAVAILABLE',alert='VAULT_UNAVAILABLE',reason='VAULT_UNAVAILABLE');return result
        result['vault']='AVAILABLE'
    except Exception:
        result.update(vault='UNAVAILABLE',alert='VAULT_UNAVAILABLE',reason='VAULT_UNAVAILABLE');return result
    rotation=assess_rotation(history,campaign_id,anchor_provider=anchor_provider,resolver=secret_resolver,
                            policy_provider=policy_provider,now=now,warning_seconds=warning_seconds)
    result['integrity']=rotation.get('integrity','UNVERIFIED')
    result['rotation']=rotation.get('rotation','UNVERIFIED')
    result['reason']=rotation.get('reason','SECURITY_UNVERIFIED')
    if result['integrity']!='VERIFIED':result['alert']='ANCHOR_UNVERIFIED'
    elif result['rotation']=='EXPIRING':
        result.update(alert='KEY_EXPIRING',manual_renewal_recommended=True)
    elif result['rotation']=='CURRENT':result['alert']='NONE'
    else:result['alert']='KEY_'+result['rotation']
    return result

def create_vault_operations_app(*,history_path,registry_path,resolve_verified_principal,
    get_netapp_inventories,get_netapp_differences,get_lif_evidence,get_campaign_reports,
    anchor_provider,secret_resolver,policy_provider,vault_health):
    """Extend existing authenticated Operations with JSON + HTML security summary."""
    from html import escape
    from fastapi import Request,HTTPException
    from fastapi.responses import JSONResponse,HTMLResponse
    from odmm_anchor_rotation_v2099 import create_rotation_operations_app
    from odmm_campaign_history_v2096 import CampaignHistory
    from odmm_operations_security import make_request_authorizer
    app=create_rotation_operations_app(history_path=history_path,registry_path=registry_path,
        resolve_verified_principal=resolve_verified_principal,get_netapp_inventories=get_netapp_inventories,
        get_netapp_differences=get_netapp_differences,get_lif_evidence=get_lif_evidence,
        get_campaign_reports=get_campaign_reports,anchor_provider=anchor_provider,
        secret_resolver=secret_resolver,policy_provider=policy_provider)
    authorize=make_request_authorizer(resolve_verified_principal)
    history=CampaignHistory(history_path)
    async def data(request:Request,campaign_id:str):
        try:
            if authorize(request) is not True:raise HTTPException(403,'FORBIDDEN')
        except HTTPException:raise
        except Exception:raise HTTPException(403,'FORBIDDEN')
        return assess_vault_campaign(history,campaign_id,anchor_provider=anchor_provider,
            secret_resolver=secret_resolver,policy_provider=policy_provider,vault_health=vault_health)
    async def api(request:Request,campaign_id:str):
        return JSONResponse(await data(request,campaign_id),headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    async def page(request:Request,campaign_id:str):
        r=await data(request,campaign_id)
        fields=('vault','integrity','rotation','alert','reason')
        rows=''.join('<li>'+escape(k)+': '+escape(str(r[k]),quote=True)+'</li>' for k in fields)
        html='<html lang="fr"><meta charset="utf-8"><title>ODMM Sécurité Vault</title><main><h1>Campagne '+escape(campaign_id,quote=True)+'</h1><strong>Cutover bloqué</strong><ul>'+rows+'</ul><p>Auteur : Abdelhalim Talbi</p></main></html>'
        return HTMLResponse(html,headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
            'Content-Security-Policy':"default-src 'none';frame-ancestors 'none';base-uri 'none'"})
    app.add_api_route('/api/v1/operations/netapp/campaigns/{campaign_id}/vault-security',api,methods=['GET'])
    app.add_api_route('/operations/netapp/campaigns/{campaign_id}/vault-security',page,methods=['GET'],include_in_schema=False)
    return app
