"""ODMM vault readiness, advisory only. Author: Abdelhalim Talbi.

No secret is persisted, displayed or rotated. A trusted adapter is injected by deployment.
"""
from datetime import datetime, timezone
from odmm_anchor_rotation_v2099 import assess_rotation


def assess_vault_readiness(history, campaign_id, *, anchor_provider, resolver, policy_provider,
                           vault_probe, now=None, warning_seconds=604800):
    """Verify anchor, policy and vault metadata; never authorize cutover."""
    base = assess_rotation(history, campaign_id, anchor_provider=anchor_provider,
                           resolver=resolver, policy_provider=policy_provider,
                           now=now, warning_seconds=warning_seconds)
    base.update(schema='odmm.vault.readiness.v2100', vault='UNVERIFIED',
                renewal_action='BLOCK_AND_INVESTIGATE', cutover_authorized=False,
                status='BLOCKED')
    if base['integrity'] != 'VERIFIED' or base['rotation'] not in ('CURRENT', 'EXPIRING'):
        return base
    try:
        if not callable(vault_probe):
            raise ValueError('VAULT_PROBE_UNAVAILABLE')
        metadata = vault_probe(base['key_id'])
        if not isinstance(metadata, dict) or set(metadata) != {'key_id', 'reachable', 'version', 'enabled'}:
            raise ValueError('INVALID_VAULT_METADATA')
        if metadata['key_id'] != base['key_id'] or not isinstance(metadata['version'], str) or not metadata['version'] or len(metadata['version']) > 128:
            raise ValueError('VAULT_KEY_MISMATCH')
        if metadata['reachable'] is not True or metadata['enabled'] is not True:
            raise ValueError('VAULT_KEY_UNAVAILABLE')
        base['vault'] = 'READY'
        base['renewal_action'] = 'PLAN_MANUAL_ROTATION' if base['rotation'] == 'EXPIRING' else 'NONE'
        base['reason'] = 'VAULT_AND_ANCHOR_VERIFIED'
    except Exception as exc:
        base['reason'] = str(exc) if str(exc) in {'VAULT_PROBE_UNAVAILABLE', 'INVALID_VAULT_METADATA', 'VAULT_KEY_MISMATCH', 'VAULT_KEY_UNAVAILABLE'} else 'VAULT_PROBE_FAILED'
    return base


def create_vault_operations_app(*, history_path, registry_path, resolve_verified_principal,
    get_netapp_inventories, get_netapp_differences, get_lif_evidence, get_campaign_reports,
    anchor_provider, secret_resolver, policy_provider, vault_probe):
    """Add authenticated no-store, read-only API and escaped HTML."""
    from html import escape
    from fastapi import Request, HTTPException
    from fastapi.responses import JSONResponse, HTMLResponse
    from odmm_anchor_rotation_v2099 import create_rotation_operations_app
    from odmm_campaign_history_v2096 import CampaignHistory
    from odmm_operations_security import make_request_authorizer
    app = create_rotation_operations_app(history_path=history_path, registry_path=registry_path,
        resolve_verified_principal=resolve_verified_principal, get_netapp_inventories=get_netapp_inventories,
        get_netapp_differences=get_netapp_differences, get_lif_evidence=get_lif_evidence,
        get_campaign_reports=get_campaign_reports, anchor_provider=anchor_provider,
        secret_resolver=secret_resolver, policy_provider=policy_provider)
    history = CampaignHistory(history_path)
    authorize = make_request_authorizer(resolve_verified_principal)
    async def result(request: Request, campaign_id: str):
        try:
            if authorize(request) is not True:
                raise HTTPException(403, 'FORBIDDEN')
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(403, 'FORBIDDEN')
        return assess_vault_readiness(history, campaign_id, anchor_provider=anchor_provider,
            resolver=secret_resolver, policy_provider=policy_provider, vault_probe=vault_probe)
    async def api(request: Request, campaign_id: str):
        return JSONResponse(await result(request, campaign_id), headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    async def page(request: Request, campaign_id: str):
        data = await result(request, campaign_id)
        body = ('<html lang="fr"><meta charset="utf-8"><title>ODMM Vault</title><main>'
            '<h1>Qualification coffre '+escape(campaign_id, quote=True)+'</h1>'
            '<strong>Cutover bloqué</strong><p>Ancrage : '+escape(data['integrity'])+'</p>'
            '<p>Rotation : '+escape(data['rotation'])+'</p><p>Coffre : '+escape(data['vault'])+'</p>'
            '<p>Action : '+escape(data['renewal_action'])+'</p><p>Motif : '+escape(data['reason'])+'</p></main></html>')
        return HTMLResponse(body, headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
            'Content-Security-Policy':"default-src 'none';frame-ancestors 'none';base-uri 'none'"})
    app.add_api_route('/api/v1/operations/netapp/campaigns/{campaign_id}/vault-readiness', api, methods=['GET'])
    app.add_api_route('/operations/netapp/campaigns/{campaign_id}/vault-readiness', page, methods=['GET'], include_in_schema=False)
    return app
