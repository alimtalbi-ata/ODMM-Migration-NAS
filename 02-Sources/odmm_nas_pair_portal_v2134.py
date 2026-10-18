"""Fail-closed, read-only NAS pair qualification portal. Author: Abdelhalim Talbi."""
from html import escape
from odmm_nas_share_inventory_v2133 import NamespaceEvidence, compare_namespaces

VENDORS = ('netapp_ontap', 'pure_flashblade', 'dell_onefs')


def _authorized(authorize, request):
    try:
        return authorize(request) is True
    except Exception:
        return False


def _safe_inventory(provider, vendor):
    value = provider()
    if type(value) is not NamespaceEvidence or value.vendor != vendor or value.certified is not False or value.cutover_authorized is not False:
        raise ValueError('UNTRUSTED_INVENTORY')
    if not isinstance(value.digest, str) or len(value.digest) != 64 or not value.blockers:
        raise ValueError('INVALID_EVIDENCE')
    return value


def attach_nas_pair_portal(app, *, authorize, providers):
    """Providers are trusted server-side callables returning qualified NamespaceEvidence."""
    if not callable(authorize) or type(providers) is not dict or set(providers) != set(VENDORS) or not all(callable(p) for p in providers.values()):
        raise ValueError('TRUSTED_AUTHORIZER_AND_THREE_PROVIDERS_REQUIRED')
    from fastapi import Request
    from fastapi.responses import JSONResponse, HTMLResponse

    def report(request, source, target):
        headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}
        if not _authorized(authorize, request):
            return JSONResponse({'error':'ACCESS_DENIED'}, status_code=403, headers=headers)
        if source not in VENDORS or target not in VENDORS or source == target:
            return JSONResponse({'error':'UNSUPPORTED_DIRECTION'}, status_code=400, headers=headers)
        try:
            a = _safe_inventory(providers[source], source)
            b = _safe_inventory(providers[target], target)
            result = compare_namespaces(a, b)
            result['source_exports'] = len(a.exports)
            result['target_exports'] = len(b.exports)
            result['source_shares'] = len(a.shares)
            result['target_shares'] = len(b.shares)
            result['cutover_authorized'] = False
        except Exception:
            return JSONResponse({'error':'EVIDENCE_UNAVAILABLE', 'cutover_authorized':False}, status_code=503, headers=headers)
        return JSONResponse(result, headers=headers)

    @app.get('/api/v1/operations/nas-pairs/{source}/{target}')
    def compare(request: Request, source: str, target: str):
        return report(request, source, target)

    @app.get('/operations/nas-pairs')
    def portal(request: Request):
        headers = {'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff',
                   'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'"}
        if not _authorized(authorize, request):
            return HTMLResponse('Access denied', status_code=403, headers=headers)
        rows=[]
        import json
        for source in VENDORS:
            for target in VENDORS:
                if source == target:
                    continue
                response=report(request,source,target)
                if response.status_code == 200:
                    data=json.loads(response.body)
                    gaps=len(data['missing_nfs'])+len(data['missing_smb'])
                    detail=f'{gaps} missing namespaces; {len(data["blockers"])} blockers'
                else:
                    detail='Evidence unavailable'
                rows.append('<tr><td>'+escape(source)+'</td><td>'+escape(target)+'</td><td>'+escape(detail)+'</td><td>BLOCKED</td></tr>')
        style='body{font:15px system-ui;background:#0b1424;color:#e7eefc;padding:2rem}main{max-width:1100px;margin:auto}table{width:100%;border-collapse:collapse;background:#15243a}td,th{padding:12px;border-bottom:1px solid #32445b;text-align:left}th{color:#8de0e0}.warn{color:#ffc987}'
        page='<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ODMM NAS Pair Qualification</title><style>'+style+'</style></head><body><main><h1>ODMM — Qualification NAS</h1><p>NetApp ONTAP · Pure FlashBlade · Dell PowerScale / OneFS</p><p class="warn">Lecture seule — aucune bascule autorisée. Inventaires issus des collecteurs serveur.</p><table><thead><tr><th>Source</th><th>Cible</th><th>Écarts / preuves</th><th>Gate</th></tr></thead><tbody>'+''.join(rows)+'</tbody></table><p>Auteur : Abdelhalim Talbi</p></main></body></html>'
        return HTMLResponse(page,headers=headers)
