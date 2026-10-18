"""Consolidated, read-only qualification report; not a production certification.
Author: Abdelhalim Talbi.
"""
import html
import json
import sqlite3
from pathlib import Path
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from qualification_matrix_v2209 import _matrix
from qualification_portal_v2206 import HEADERS


def _report(db_path, older, newer):
    matrix = _matrix(db_path, older, newer)
    try:
        with sqlite3.connect(f'file:{Path(db_path).resolve()}?mode=ro', uri=True) as con:
            rows = con.execute('SELECT id,status,browser_status,evidence_sha256,windows_qualified FROM runs WHERE id IN (?,?)', (older, newer)).fetchall()
        if len(rows) != 2 or any(r[4] != 0 for r in rows):
            raise ValueError('INVALID_RUN_ATTESTATION')
        runs = {r[0]: {'id':r[0], 'status':r[1], 'browser_status':r[2], 'evidence_sha256':r[3]} for r in rows}
        if any(not isinstance(r['evidence_sha256'],str) or len(r['evidence_sha256']) != 64 or any(c not in '0123456789abcdef' for c in r['evidence_sha256']) for r in runs.values()):
            raise ValueError('INVALID_EVIDENCE_DIGEST')
        counts = {s:sum(item['state']==s for item in matrix) for s in ('REGRESSION','IMPROVEMENT','ADDED','REMOVED','UNCHANGED_PASS','UNCHANGED_FAIL')}
        return {'schema':'odmm.qualification.global.v2210','older':runs[older], 'newer':runs[newer], 'counts':counts,
                'controls':matrix, 'read_only':True,'windows_qualified':False,'nas_qualified':False,'cutover_authorized':False,
                'verdict':'REVIEW_REQUIRED' if counts['REGRESSION'] or counts['REMOVED'] or counts['UNCHANGED_FAIL'] or counts['ADDED'] else 'NO_DETECTED_REGRESSION_NOT_CERTIFIED'}
    except (sqlite3.DatabaseError,OSError,ValueError,TypeError,KeyError) as exc:
        raise HTTPException(503,'QUALIFICATION_GLOBAL_UNAVAILABLE') from exc


def attach_qualification_global(app, *, authorize, db_path):
    if not callable(authorize) or not hasattr(app,'add_api_route') or not db_path:
        raise ValueError('AUTHORIZATION_AND_APP_AND_DB_REQUIRED')
    def guarded(request, older, newer):
        if authorize(request) is not True:
            raise HTTPException(403,'FORBIDDEN')
        return _report(db_path,older,newer)
    async def export(request:Request,older:int,newer:int):
        return JSONResponse(guarded(request,older,newer),headers=HEADERS)
    async def page(request:Request,older:int,newer:int):
        report=guarded(request,older,newer)
        e=lambda v:html.escape(str(v),quote=True)
        rows=''.join('<tr><td>'+e(r['check'])+'</td><td>'+e(r['older'])+'</td><td>'+e(r['newer'])+'</td><td>'+e(r['state'])+'</td></tr>' for r in report['controls'])
        cards=''.join('<li>'+e(k)+': '+str(v)+'</li>' for k,v in report['counts'].items())
        content=('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM · Qualification consolidée</title>'
                 '<style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:1rem;color:#17344b}table{border-collapse:collapse;width:100%}td,th{padding:.65rem;border-bottom:1px solid #ddd;text-align:left}</style>'
                 '<h1>Qualification consolidée</h1><p>Lecture seule · Windows et NAS non certifiés · Cutover interdit</p>'
                 '<p>Verdict : '+e(report['verdict'])+'</p><ul>'+cards+'</ul><p><a href="/api/v1/operations/qualification-history/global.json?older='+str(older)+'&amp;newer='+str(newer)+'">Exporter JSON</a></p>'
                 '<table><thead><tr><th>Contrôle</th><th>Avant</th><th>Après</th><th>Évolution</th></tr></thead><tbody>'+rows+'</tbody></table><footer>Auteur : Abdelhalim Talbi</footer></html>')
        return HTMLResponse(content,headers={**HEADERS,'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"})
    app.add_api_route('/operations/qualification-history/global',page,methods=['GET'],include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history/global.json',export,methods=['GET'],include_in_schema=False)
    return page
