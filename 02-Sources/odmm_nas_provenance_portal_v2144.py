"""Authenticated read-only provenance dashboard; no NAS hardware certification.
Author: Abdelhalim Talbi.
"""
from html import escape
from datetime import datetime, timezone
from odmm_nas_effective_access_v2137 import VENDORS
from odmm_nas_provenance_v2143 import compare_fresh_provenance


def attach_provenance_dashboard(app, *, authorize, providers, clock=None):
    if not callable(authorize) or type(providers) is not dict or set(providers) != VENDORS or not all(callable(x) for x in providers.values()):
        raise ValueError('AUTHORIZER_AND_PROVIDERS_REQUIRED')
    if clock is not None and not callable(clock):
        raise ValueError('INVALID_CLOCK')
    from fastapi import Request
    from fastapi.responses import HTMLResponse, JSONResponse
    headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
             'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"}
    def authorized(request):
        try: return authorize(request) is True
        except Exception: return False
    def collect(source,target):
        now=clock() if clock is not None else datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        result=compare_fresh_provenance(providers[source](),providers[target](),now=now)
        return result
    @app.get('/api/v1/operations/nas-provenance/{source}/{target}')
    def provenance_api(request:Request,source:str,target:str):
        if not authorized(request): return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=headers)
        if source not in VENDORS or target not in VENDORS or source==target:
            return JSONResponse({'error':'UNSUPPORTED_DIRECTION'},status_code=400,headers=headers)
        try: result=collect(source,target)
        except Exception: return JSONResponse({'error':'EVIDENCE_UNAVAILABLE','cutover_authorized':False},status_code=503,headers=headers)
        return JSONResponse(result,headers=headers)
    @app.get('/operations/nas-provenance')
    def provenance_html(request:Request, source:str='',target:str='',only:str='all'):
        if not authorized(request): return HTMLResponse('Access denied',status_code=403,headers=headers)
        if source and source not in VENDORS or target and target not in VENDORS or only not in ('all','mismatch','blocked'):
            return HTMLResponse('Invalid filter',status_code=400,headers=headers)
        rows=[]
        for s in VENDORS:
            for t in VENDORS:
                if s==t or source and s!=source or target and t!=target: continue
                try:
                    r=collect(s,t)
                    n=len(r['discrepancies'])
                    if only=='mismatch' and n==0: continue
                    status='BLOCKED'; fresh='YES'
                    detail='; '.join(str(x) for x in r['blockers'])
                    dig=r['provenance']['source_envelope_digest'][:16]+'… / '+r['provenance']['target_envelope_digest'][:16]+'…'
                except Exception:
                    n='—'; status='UNAVAILABLE'; fresh='NO'; detail='Evidence unavailable or expired'; dig='—'
                    if only=='mismatch': continue
                rows.append('<tr>'+''.join('<td>'+escape(str(x),quote=True)+'</td>' for x in (s,t,status,fresh,n,dig,detail))+'</tr>')
        html=('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM — Provenance NAS</title>'
              '<style>body{font:15px system-ui;background:#101b2b;color:#edf3fa;padding:2rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #456;padding:.6rem;text-align:left}th{background:#234}code{overflow-wrap:anywhere}</style>'
              '<h1>ODMM — Fraîcheur et provenance NAS</h1><p>Lecture seule · Bascule interdite · Auteur : Abdelhalim Talbi</p>'
              '<p>Filtres : source='+escape(source or 'toutes')+' ; cible='+escape(target or 'toutes')+' ; type='+escape(only)+'</p>'
              '<table><thead><tr><th>Source</th><th>Cible</th><th>État</th><th>Fraîcheur</th><th>Écarts</th><th>Empreintes</th><th>Blocages</th></tr></thead><tbody>'
              +(''.join(rows) if rows else '<tr><td colspan="7">Aucun résultat</td></tr>')+'</tbody></table>'
              '<p>Empreintes non attestées cryptographiquement. Horloges des collecteurs non qualifiées.</p></html>')
        return HTMLResponse(html,headers=headers)
