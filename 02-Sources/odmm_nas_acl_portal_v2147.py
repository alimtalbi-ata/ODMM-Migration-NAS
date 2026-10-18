"""Authenticated, privacy-preserving ACL audit view. Author: Abdelhalim Talbi.
Read-only synthetic integration; vendor-effective permissions NOT certified.
"""
from html import escape
from hashlib import sha256
import json
from odmm_nas_acl_semantics_v2146 import VENDORS, compare_acl_semantics

HEADERS={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"}

def attach_acl_audit_portal(app, *, authorize, providers):
    if not callable(authorize) or type(providers) is not dict or set(providers)!=VENDORS or not all(callable(p) for p in providers.values()):
        raise ValueError('INVALID_ACL_PORTAL_DEPENDENCIES')
    from fastapi import Request
    from fastapi.responses import HTMLResponse, JSONResponse
    def allowed(req):
        try: return authorize(req) is True
        except Exception: return False
    def summary(s,t,protocol):
        a=providers[s](protocol); b=providers[t](protocol)
        report=compare_acl_semantics(a,b)
        return {'source':s,'target':t,'protocol':protocol,'status':'BLOCKED','cutover_authorized':False,
                'issues':report['issues'],'issue_count':len(report['issues']),
                'source_digest':report['source_digest'],'target_digest':report['target_digest'],
                'report_digest':report['report_digest'],'blockers':report['blockers'],
                'share_fingerprint':sha256(a['share'].encode()).hexdigest()[:16]}
    @app.get('/api/v1/operations/nas-acl-audit')
    def api(request:Request, source:str='', target:str='', protocol:str='NFS4', only:str='all'):
        if not allowed(request): return JSONResponse({'error':'ACCESS_DENIED'},status_code=403,headers=HEADERS)
        if (source and source not in VENDORS) or (target and target not in VENDORS) or protocol not in ('NFS4','SMB3') or only not in ('all','mismatch'):
            return JSONResponse({'error':'INVALID_FILTER'},status_code=400,headers=HEADERS)
        reports=[]; unavailable=0
        for s in sorted(VENDORS):
            for t in sorted(VENDORS):
                if s==t or (source and s!=source) or (target and t!=target): continue
                try:
                    item=summary(s,t,protocol)
                    if only=='mismatch' and not item['issues']: continue
                    reports.append(item)
                except Exception:
                    unavailable+=1
                    reports.append({'source':s,'target':t,'protocol':protocol,'status':'UNAVAILABLE','cutover_authorized':False,'issues':[],'issue_count':None,'blockers':['EVIDENCE_UNAVAILABLE']})
        return JSONResponse({'schema':'odmm.nas.acl.audit.v2147','reports':reports,'unavailable':unavailable,'cutover_authorized':False,'author':'Abdelhalim Talbi'},headers=HEADERS)
    @app.get('/operations/nas-acl-audit')
    def html(request:Request, source:str='',target:str='',protocol:str='NFS4',only:str='all'):
        response=api(request,source,target,protocol,only)
        if response.status_code!=200: return HTMLResponse('Access denied' if response.status_code==403 else 'Invalid filter',status_code=response.status_code,headers=HEADERS)
        payload=json.loads(response.body)
        rows=''.join('<tr>'+''.join('<td>'+escape(str(x),quote=True)+'</td>' for x in (r['source'],r['target'],r['protocol'],r['status'],r['issue_count'],', '.join(r['issues']),', '.join(r['blockers'])))+'</tr>' for r in payload['reports'])
        page=('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM — Audit ACL NAS</title>'
              '<style>body{font:15px system-ui;background:#101b2b;color:#edf3fa;padding:2rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #456;padding:.6rem;text-align:left}th{background:#234}</style>'
              '<h1>Audit ACL NFSv4 / SMB3</h1><p>Lecture seule · Cutover interdit · Auteur : Abdelhalim Talbi</p>'
              '<form method="get"><label>Source <select name="source"><option value="">Toutes</option>'
              +''.join('<option value="'+escape(v)+'"'+(' selected' if source==v else '')+'>'+escape(v)+'</option>' for v in sorted(VENDORS))+'</select></label>'
              '<label>Cible <select name="target"><option value="">Toutes</option>'
              +''.join('<option value="'+escape(v)+'"'+(' selected' if target==v else '')+'>'+escape(v)+'</option>' for v in sorted(VENDORS))+'</select></label>'
              '<label>Protocole <select name="protocol">'+''.join('<option'+(' selected' if protocol==v else '')+'>'+v+'</option>' for v in ('NFS4','SMB3'))+'</select></label>'
              '<label>Écarts <select name="only">'+''.join('<option'+(' selected' if only==v else '')+'>'+v+'</option>' for v in ('all','mismatch'))+'</select></label><button>Filtrer</button></form>'
              '<table><thead><tr><th>Source</th><th>Cible</th><th>Protocole</th><th>État</th><th>Nombre</th><th>Écarts</th><th>Blocages</th></tr></thead><tbody>'
              +(rows or '<tr><td colspan="7">Aucun résultat</td></tr>')+'</tbody></table>'
              '<p>Identités, chemins et ACE brutes masqués. Analyse indicative, non certifiée sur matériel.</p></html>')
        return HTMLResponse(page,headers=HEADERS)
