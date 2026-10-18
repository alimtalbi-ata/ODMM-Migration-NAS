"""Read-only graphical comparison selector and consolidated export. Author: Abdelhalim Talbi."""
import html
import sqlite3
from pathlib import Path
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from qualification_history_v2205 import history, compare
from qualification_portal_v2206 import HEADERS


def attach_qualification_comparison(app, *, authorize, db_path):
    if not callable(authorize) or not hasattr(app, 'add_api_route') or not db_path:
        raise ValueError('AUTHORIZATION_AND_APP_AND_DB_REQUIRED')
    db = Path(db_path)
    def guard(request):
        if authorize(request) is not True:
            raise HTTPException(403, 'FORBIDDEN')
    def safe(fn):
        try:
            if not db.is_file():
                raise FileNotFoundError('DB_MISSING')
            return fn()
        except (OSError, ValueError, KeyError, TypeError, sqlite3.DatabaseError) as exc:
            raise HTTPException(503, 'QUALIFICATION_HISTORY_UNAVAILABLE') from exc
    def comparison(older, newer):
        if older < 1 or newer < 1 or older >= newer:
            raise HTTPException(422, 'INVALID_RUN_ORDER')
        return safe(lambda: compare(db, older, newer))
    async def selector(request: Request, older: int | None = None, newer: int | None = None):
        guard(request)
        runs = safe(lambda: history(db, 100))
        ids = {r['id'] for r in runs}
        if older is None and newer is None:
            older, newer = (runs[1]['id'], runs[0]['id']) if len(runs) >= 2 else (None, None)
        elif older is None or newer is None:
            raise HTTPException(422, 'BOTH_IDS_REQUIRED')
        if older is not None and (older not in ids or newer not in ids):
            raise HTTPException(422, 'RUN_NOT_IN_SELECTION')
        data = comparison(older, newer) if older is not None else None
        esc = lambda x: html.escape(str(x), quote=True)
        opts = lambda selected: ''.join(f'<option value="{r["id"]}"'+(' selected' if r['id']==selected else '')+f'>{r["id"]} · {esc(r["status"])} · {esc(r["recorded_at"])}</option>' for r in runs)
        sections = '' if data is None else ''.join('<section><h2>'+esc(label)+' ('+str(len(data[key]))+')</h2><ul>'+(''.join('<li>'+esc(x)+'</li>' for x in data[key]) or '<li>Aucun</li>')+'</ul></section>' for key,label in [('regressions','Régressions'),('improvements','Améliorations'),('new_failures','Nouvelles anomalies')])
        link = '' if data is None else (f'<p><a href="/api/v1/operations/qualification-history/comparison-report?older={older}&newer={newer}">Exporter le rapport JSON</a> · <a href="/operations/qualification-history/matrix?older={older}&newer={newer}">Matrice des contrôles</a></p>')
        page = ('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM · Comparer les recettes</title>'
                '<style>body{font:16px system-ui;max-width:1050px;margin:2rem auto;padding:0 1rem;color:#17344b}form{display:flex;flex-wrap:wrap;gap:1rem;align-items:end}label{display:grid;gap:.3rem}select,button{padding:.65rem;max-width:420px}section{padding:1rem;border:1px solid #cad6df;border-radius:10px;margin-top:1rem}li{padding:.25rem}</style>'
                '<h1>Comparaison des recettes</h1><p>Lecture seule · Non certifié Windows · Cutover interdit</p><a href="/operations/qualification-history/insights">Historique</a>'
                '<form method="get"><label>Exécution ancienne<select name="older">'+opts(older)+'</select></label>'
                '<label>Exécution récente<select name="newer">'+opts(newer)+'</select></label><button>Comparer</button></form>'+sections+link+'<footer>Auteur : Abdelhalim Talbi</footer></html>')
        return HTMLResponse(page, headers=HEADERS)
    async def export(request: Request, older: int, newer: int):
        guard(request)
        data = comparison(older, newer)
        return JSONResponse({'schema':'odmm.qualification.comparison.v2208','comparison':data,
                             'counts':{key:len(data[key]) for key in ('regressions','improvements','new_failures')},
                             'read_only':True,'windows_qualified':False,'cutover_authorized':False},headers=HEADERS)
    app.add_api_route('/operations/qualification-history/compare-select', selector, methods=['GET'], include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history/comparison-report', export, methods=['GET'], include_in_schema=False)
    return selector
