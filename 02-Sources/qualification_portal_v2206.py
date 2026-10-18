"""Read-only, authorized qualification history UI. Author: Abdelhalim Talbi."""
import html
from pathlib import Path
from qualification_history_v2205 import history, compare

HEADERS = {'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer', 'X-Frame-Options':'DENY', 'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"}

def attach_qualification_history(app, *, authorize, db_path):
    if not callable(authorize) or not hasattr(app, 'add_api_route') or not db_path:
        raise ValueError('AUTHORIZATION_AND_APP_AND_DB_REQUIRED')
    from fastapi import HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    db = Path(db_path)
    def access(request):
        if authorize(request) is not True:
            raise HTTPException(403, 'FORBIDDEN')
    def load(fn):
        try:
            if not db.is_file():
                raise FileNotFoundError('no database')
            return fn()
        except (OSError, ValueError, KeyError, TypeError, __import__('sqlite3').DatabaseError) as exc:
            raise HTTPException(503, 'QUALIFICATION_HISTORY_UNAVAILABLE') from exc
    async def page(request: Request, limit: int = 50):
        access(request)
        if not 1 <= limit <= 100: raise HTTPException(422, 'INVALID_LIMIT')
        rows = load(lambda: history(db, limit))
        body = ''.join('<tr><td>'+str(r['id'])+'</td><td>'+html.escape(r['recorded_at'])+'</td><td>'+html.escape(r['status'])+'</td><td>'+html.escape(r['browser_status'])+'</td><td>'+str(len(r['failures']))+'</td></tr>' for r in rows)
        page_html = '<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM · Recettes Windows</title><style>body{font:16px system-ui;margin:3rem;max-width:1100px;color:#14243b}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #cbd5e1;padding:12px;text-align:left}a{color:#1757a5}</style><h1>Historique des recettes navigateur</h1><p>Lecture seule · Aucun résultat ne certifie Windows ni n’autorise le cutover.</p><p><a href="/operations">Retour aux opérations</a> · <a href="/api/v1/operations/qualification-history">Export JSON</a></p><table><thead><tr><th>ID</th><th>Date UTC</th><th>Résultat</th><th>Navigateur</th><th>Anomalies</th></tr></thead><tbody>'+body+'</tbody></table><p>Auteur : Abdelhalim Talbi</p></html>'
        return HTMLResponse(page_html, headers=HEADERS)
    async def export(request: Request, limit: int = 50):
        access(request)
        if not 1 <= limit <= 100: raise HTTPException(422, 'INVALID_LIMIT')
        return JSONResponse({'runs':load(lambda: history(db,limit)), 'windows_qualified':False}, headers=HEADERS)
    async def diff(request: Request, older: int, newer: int):
        access(request)
        if older < 1 or newer < 1 or older == newer: raise HTTPException(422, 'INVALID_RUN_IDS')
        return JSONResponse(load(lambda: compare(db,older,newer)), headers=HEADERS)
    app.add_api_route('/operations/qualification-history',page,methods=['GET'],include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history',export,methods=['GET'],include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history/compare',diff,methods=['GET'],include_in_schema=False)
    return page
