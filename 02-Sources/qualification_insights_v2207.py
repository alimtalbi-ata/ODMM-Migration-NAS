"""Read-only qualification insights and comparison pages. Author: Abdelhalim Talbi."""
import html
import sqlite3
from pathlib import Path
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from qualification_history_v2205 import history, compare
from qualification_portal_v2206 import HEADERS


def summarize(rows, status='ALL', search=''):
    if status not in ('ALL', 'PASS', 'FAIL', 'NOT_EXECUTED'):
        raise ValueError('INVALID_STATUS')
    if len(search) > 120:
        raise ValueError('SEARCH_TOO_LONG')
    selected = [r for r in rows if (status == 'ALL' or r['status'] == status) and
                (not search or search.casefold() in (str(r['id'])+' '+r['status']+' '+r['browser_status']+' '+' '.join(map(str, r['failures']))).casefold())]
    return {'total': len(selected), 'pass': sum(r['status']=='PASS' for r in selected),
            'fail': sum(r['status']=='FAIL' for r in selected),
            'not_executed': sum(r['status']=='NOT_EXECUTED' for r in selected),
            'runs': selected, 'windows_qualified': False, 'cutover_authorized': False}


def attach_qualification_insights(app, *, authorize, db_path):
    if not callable(authorize) or not hasattr(app, 'add_api_route') or not db_path:
        raise ValueError('AUTHORIZATION_AND_APP_AND_DB_REQUIRED')
    db = Path(db_path)
    def access(request):
        if authorize(request) is not True:
            raise HTTPException(403, 'FORBIDDEN')
    def load(fn):
        try:
            if not db.is_file():
                raise FileNotFoundError('DB_MISSING')
            return fn()
        except (OSError, ValueError, KeyError, TypeError, sqlite3.DatabaseError) as exc:
            raise HTTPException(503, 'QUALIFICATION_HISTORY_UNAVAILABLE') from exc
    def validate(status, search, limit):
        if status not in ('ALL','PASS','FAIL','NOT_EXECUTED') or len(search)>120 or not 1<=limit<=100:
            raise HTTPException(422,'INVALID_FILTER')
    async def insights(request: Request, status: str='ALL', search: str='', limit: int=50):
        access(request); validate(status,search,limit)
        result = load(lambda: summarize(history(db,limit),status,search))
        def esc(x): return html.escape(str(x), quote=True)
        rows = ''.join('<tr><td>'+esc(r['id'])+'</td><td>'+esc(r['recorded_at'])+'</td><td>'+esc(r['status'])+'</td><td>'+esc(r['browser_status'])+'</td><td>'+esc(len(r['failures']))+'</td></tr>' for r in result['runs'])
        page = ('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM · Qualité des recettes</title>'
                '<style>body{font:16px system-ui;margin:2rem auto;max-width:1100px;color:#183047}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ccd7e0;padding:10px;text-align:left}.metrics{display:flex;gap:1rem;flex-wrap:wrap}.metrics b{border:1px solid #ccd7e0;border-radius:8px;padding:1rem}input,select,button{padding:.5rem}</style>'
                '<h1>Qualification · Historique et anomalies</h1><p>Lecture seule · Non certifié Windows · Cutover interdit</p>'
                '<p><a href="/operations">Opérations</a> · <a href="/operations/qualification-history">Historique</a></p>'
                '<form method="get"><label>Résultat <select name="status">'+''.join('<option value="'+esc(s)+'"'+(' selected' if s==status else '')+'>'+esc(s)+'</option>' for s in ('ALL','PASS','FAIL','NOT_EXECUTED'))+'</select></label> '
                '<label>Recherche <input name="search" maxlength="120" value="'+esc(search)+'"></label> '
                '<label>Limite <input name="limit" type="number" min="1" max="100" value="'+esc(limit)+'"></label><button>Filtrer</button></form>'
                '<div class="metrics">'+''.join('<b>'+esc(k)+': '+esc(result[k])+'</b>' for k in ('total','pass','fail','not_executed'))+'</div>'
                '<table><thead><tr><th>ID</th><th>Date UTC</th><th>Statut</th><th>Navigateur</th><th>Anomalies</th></tr></thead><tbody>'+rows+'</tbody></table><p>Auteur : Abdelhalim Talbi</p></html>')
        return HTMLResponse(page,headers=HEADERS)
    async def export(request: Request,status: str='ALL',search: str='',limit: int=50):
        access(request);validate(status,search,limit)
        return JSONResponse(load(lambda:summarize(history(db,limit),status,search)),headers=HEADERS)
    async def comparison(request: Request,older: int,newer: int):
        access(request)
        if older<1 or newer<1 or older==newer: raise HTTPException(422,'INVALID_RUN_IDS')
        data=load(lambda:compare(db,older,newer))
        def section(key):
            return '<h2>'+html.escape({'regressions':'Régressions','improvements':'Améliorations','new_failures':'Nouvelles anomalies'}[key])+'</h2><ul>'+''.join('<li>'+html.escape(str(x))+'</li>' for x in data[key])+'</ul>'
        body='<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM · Comparaison</title><h1>Comparaison des recettes '+str(older)+' → '+str(newer)+'</h1><p>Lecture seule · Aucun cutover autorisé</p>'+''.join(section(k) for k in ('regressions','improvements','new_failures'))+'<a href="/operations/qualification-history/insights">Retour</a></html>'
        return HTMLResponse(body,headers=HEADERS)
    app.add_api_route('/operations/qualification-history/insights',insights,methods=['GET'],include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history/insights',export,methods=['GET'],include_in_schema=False)
    app.add_api_route('/operations/qualification-history/compare',comparison,methods=['GET'],include_in_schema=False)
    return insights
