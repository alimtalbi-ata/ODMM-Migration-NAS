"""Read-only per-direction ACL evidence detail, no hardware certification.
Author: Abdelhalim Talbi.
"""
from html import escape
from odmm_nas_probe_adapters_v2138 import compare_collected_evidence
from odmm_nas_effective_access_v2137 import VENDORS


def attach_nas_access_detail(app, *, authorize, providers):
    if not callable(authorize) or type(providers) is not dict or set(providers) != VENDORS or not all(callable(p) for p in providers.values()):
        raise ValueError('AUTHORIZER_AND_PROVIDERS_REQUIRED')
    from fastapi import Request
    from fastapi.responses import HTMLResponse
    headers = {'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff',
        'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
        'Referrer-Policy':'no-referrer'}
    @app.get('/operations/nas-access/detail/{source}/{target}')
    def detail(request:Request, source:str, target:str):
        try: authorized = authorize(request) is True
        except Exception: authorized = False
        if not authorized: return HTMLResponse('Access denied', status_code=403, headers=headers)
        if source not in VENDORS or target not in VENDORS or source == target:
            return HTMLResponse('Unsupported direction', status_code=400, headers=headers)
        try: result = compare_collected_evidence(providers[source](),providers[target]())
        except Exception: return HTMLResponse('Evidence unavailable', status_code=503, headers=headers)
        rows=[]
        for item in result['discrepancies']:
            # Do not assume discrepancy tuple shape; escape every element.
            if type(item) not in (list,tuple): return HTMLResponse('Invalid evidence',status_code=503,headers=headers)
            rows.append('<tr><td>'+escape(' | '.join(str(v) for v in item))+'</td></tr>')
        blockers=''.join('<li>'+escape(str(b))+'</li>' for b in result['blockers'])
        html = ('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM — Détail des écarts NAS</title>'
          '<style>body{font:16px system-ui;background:#101b2b;color:#edf3fa;padding:2rem;max-width:1100px;margin:auto}'
          'table{border-collapse:collapse;width:100%}th,td{border:1px solid #456;padding:.7rem;text-align:left}'
          'th{background:#234}a{color:#9cd5ff}code{overflow-wrap:anywhere}</style>'
          '<h1>ODMM — Détail des écarts NAS</h1><p>Lecture seule · Bascule interdite · Auteur : Abdelhalim Talbi</p>'
          '<p><a href="/operations/nas-access">Retour au tableau de bord</a></p>'
          '<h2>'+escape(source)+' → '+escape(target)+'</h2>'
          '<p>Contrôles : '+str(result['checked'])+' · Écarts : '+str(len(rows))+' · Statut : BLOCKED</p>'
          '<h3>Écarts</h3><table><thead><tr><th>Identité / chemin / droit / décision</th></tr></thead><tbody>'
          +(''.join(rows) if rows else '<tr><td>Aucun écart observé (non certifié)</td></tr>')+'</tbody></table>'
          '<h3>Blocages de qualification</h3><ul>'+blockers+'</ul>'
          '<h3>Empreintes des preuves</h3><p>Source : <code>'+escape(result['source_digest'])+'</code></p>'
          '<p>Cible : <code>'+escape(result['target_digest'])+'</code></p>'
          '<p>Comparaison : <code>'+escape(result['comparison_digest'])+'</code></p></html>')
        return HTMLResponse(html, headers=headers)
