"""Read-only qualification check matrix and spreadsheet-safe CSV. Author: Abdelhalim Talbi."""
import csv
import html
import io
import json
import sqlite3
from pathlib import Path
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from qualification_portal_v2206 import HEADERS


def _matrix(db, older, newer):
    if older < 1 or newer < 1 or older >= newer:
        raise HTTPException(422, 'INVALID_RUN_ORDER')
    try:
        if not Path(db).is_file():
            raise OSError('missing')
        with sqlite3.connect(f'file:{Path(db).resolve()}?mode=ro', uri=True) as con:
            rows = con.execute('SELECT id, checks_json FROM runs WHERE id IN (?,?)', (older, newer)).fetchall()
        if len(rows) != 2:
            raise HTTPException(404, 'RUN_NOT_FOUND')
        checks = {}
        for rid, raw in rows:
            obj = json.loads(raw)
            if not isinstance(obj, dict) or len(obj) > 1000 or any(not isinstance(k,str) or not isinstance(v,bool) for k,v in obj.items()):
                raise ValueError('INVALID_CHECKS')
            checks[rid] = obj
        a,b = checks[older],checks[newer]
        result = []
        for name in sorted(a.keys() | b.keys()):
            old,new = a.get(name),b.get(name)
            state = ('ADDED' if name not in a else 'REMOVED' if name not in b else
                     'REGRESSION' if old and not new else 'IMPROVEMENT' if not old and new else
                     'UNCHANGED_PASS' if new else 'UNCHANGED_FAIL')
            result.append({'check':name,'older':old,'newer':new,'state':state})
        return result
    except HTTPException:
        raise
    except (OSError,sqlite3.DatabaseError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        raise HTTPException(503,'QUALIFICATION_MATRIX_UNAVAILABLE') from exc


def _csv_safe(value):
    text = '' if value is None else str(value)
    if text.lstrip().startswith(('=', '+', '-', '@', '\t', '\r', '\n')):
        return "'" + text
    return text


def attach_qualification_matrix(app, *, authorize, db_path):
    if not callable(authorize) or not hasattr(app,'add_api_route') or not db_path:
        raise ValueError('AUTHORIZATION_AND_APP_AND_DB_REQUIRED')
    def guard(request):
        if authorize(request) is not True:
            raise HTTPException(403,'FORBIDDEN')
    async def page(request:Request, older:int, newer:int, state:str='ALL'):
        guard(request)
        if state not in {'ALL','REGRESSION','IMPROVEMENT','ADDED','REMOVED','UNCHANGED_PASS','UNCHANGED_FAIL'}:
            raise HTTPException(422,'INVALID_STATE')
        items = _matrix(db_path,older,newer)
        if state != 'ALL': items = [r for r in items if r['state']==state]
        e=lambda s:html.escape(str(s),quote=True)
        cells=''.join('<tr><td>'+e(r['check'])+'</td><td>'+e(r['older'])+'</td><td>'+e(r['newer'])+'</td><td>'+e(r['state'])+'</td></tr>' for r in items)
        nav=''.join('<a href="?older='+str(older)+'&amp;newer='+str(newer)+'&amp;state='+s+'">'+s+'</a> ' for s in ('ALL','REGRESSION','IMPROVEMENT','ADDED','REMOVED'))
        markup=('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM · Matrice des contrôles</title>'
                '<style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:1rem;color:#17344b}table{border-collapse:collapse;width:100%}td,th{padding:.7rem;border-bottom:1px solid #ccd6dd;text-align:left}nav a{margin-right:.8rem}</style>'
                '<h1>Matrice de qualification</h1><p>Lecture seule · Qualification Windows non attestée · Cutover interdit</p>'
                '<nav>'+nav+'</nav><p><a href="/operations/qualification-history/compare-select?older='+str(older)+'&amp;newer='+str(newer)+'">Retour à la comparaison</a> · '
                '<a href="/api/v1/operations/qualification-history/matrix.csv?older='+str(older)+'&amp;newer='+str(newer)+'">Exporter CSV</a> · <a href="/operations/qualification-history/global?older='+str(older)+'&amp;newer='+str(newer)+'">Rapport global</a></p>'
                '<table><thead><tr><th>Contrôle</th><th>Avant</th><th>Après</th><th>Évolution</th></tr></thead><tbody>'+cells+'</tbody></table><p>Auteur : Abdelhalim Talbi</p></html>')
        return HTMLResponse(markup,headers={**HEADERS,'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"})
    async def export(request:Request,older:int,newer:int):
        guard(request)
        items=_matrix(db_path,older,newer)
        out=io.StringIO(newline='')
        writer=csv.writer(out)
        writer.writerow(['check','older','newer','state'])
        for item in items:
            writer.writerow([_csv_safe(item['check']),str(item['older']),str(item['newer']),item['state']])
        return Response(out.getvalue(),media_type='text/csv; charset=utf-8',headers={**HEADERS,'Content-Disposition':'attachment; filename="odmm-qualification-matrix.csv"'})
    app.add_api_route('/operations/qualification-history/matrix',page,methods=['GET'],include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history/matrix.csv',export,methods=['GET'],include_in_schema=False)
    return page
