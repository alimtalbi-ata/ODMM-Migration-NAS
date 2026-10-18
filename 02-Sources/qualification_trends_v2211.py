"""Read-only quality trends from recorded synthetic/browser qualifications.
Author: Abdelhalim Talbi. Never certifies Windows/NAS or authorizes cutover.
"""
import html
import json
import sqlite3
from pathlib import Path
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from qualification_portal_v2206 import HEADERS

STATES = ('PASS', 'FAIL', 'NOT_EXECUTED')

def _severity(name):
    key = name.lower()
    if any(s in key for s in ('auth', 'acl', 'security', 'csp', 'cutover', 'integrity', 'hash')):
        return 'CRITICAL'
    if any(s in key for s in ('navigation', 'filter', 'http', 'javascript')):
        return 'HIGH'
    return 'MEDIUM'

def trends(db_path, limit=30):
    if type(limit) is not int or not 2 <= limit <= 100:
        raise ValueError('INVALID_LIMIT')
    try:
        uri = Path(db_path).resolve().as_uri() + '?mode=ro'
        with sqlite3.connect(uri, uri=True) as con:
            rows = con.execute('SELECT id, recorded_at, status, checks_json, windows_qualified FROM runs ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
        if not rows:
            return {'schema':'odmm.qualification.trends.v2211','runs':[],'controls':[], 'read_only':True,'windows_qualified':False,'nas_qualified':False,'cutover_authorized':False}
        records = []
        for ident, stamp, status, checks_json, qualified in reversed(rows):
            checks = json.loads(checks_json)
            if qualified != 0 or not isinstance(checks, dict) or not all(isinstance(k,str) and type(v) is bool for k,v in checks.items()):
                raise ValueError('INVALID_ATTESTATION')
            records.append({'id':ident,'recorded_at':stamp,'status':status,'checks':checks,'passed':sum(v is True for v in checks.values()),'failed':sum(v is False for v in checks.values())})
        names = sorted(set().union(*(r['checks'].keys() for r in records)))
        controls=[]
        for name in names:
            states=[('PASS' if r['checks'][name] else 'FAIL') if name in r['checks'] else 'NOT_EXECUTED' for r in records]
            regressions=sum(a=='PASS' and b!='PASS' for a,b in zip(states,states[1:]))
            improvements=sum(a!='PASS' and b=='PASS' for a,b in zip(states,states[1:]))
            controls.append({'check':name,'severity':_severity(name),'states':states,'regressions':regressions,'improvements':improvements,'latest':states[-1]})
        return {'schema':'odmm.qualification.trends.v2211','runs':[{k:v for k,v in r.items() if k!='checks'} for r in records], 'controls':controls,'summary':{'runs':len(records),'regressions':sum(c['regressions'] for c in controls),'improvements':sum(c['improvements'] for c in controls),'open_failures':sum(c['latest']=='FAIL' for c in controls)},'read_only':True,'windows_qualified':False,'nas_qualified':False,'cutover_authorized':False}
    except (sqlite3.Error, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(503, 'QUALIFICATION_TRENDS_UNAVAILABLE') from exc

def attach_qualification_trends(app, *, authorize, db_path):
    if not callable(authorize) or not hasattr(app, 'add_api_route') or not db_path:
        raise ValueError('AUTHORIZATION_AND_APP_AND_DB_REQUIRED')
    def guarded(request, limit):
        if authorize(request) is not True:
            raise HTTPException(403, 'FORBIDDEN')
        return trends(db_path, limit)
    async def export(request:Request, limit:int=30):
        return JSONResponse(guarded(request,limit), headers=HEADERS)
    async def page(request:Request, limit:int=30):
        data=guarded(request,limit)
        e=lambda x:html.escape(str(x),quote=True)
        lines=''.join('<tr><td>'+e(c['check'])+'</td><td>'+e(c['severity'])+'</td><td>'+e(c['latest'])+'</td><td>'+str(c['regressions'])+'</td><td>'+str(c['improvements'])+'</td></tr>' for c in data['controls'])
        body='<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM · Tendances de qualification</title><h1>Tendances de qualification</h1><p>Lecture seule · Aucune certification Windows/NAS · Cutover interdit</p><p>Exécutions : '+str(len(data['runs']))+'</p><table><thead><tr><th>Contrôle</th><th>Criticité indicative</th><th>Dernier état</th><th>Régressions</th><th>Améliorations</th></tr></thead><tbody>'+lines+'</tbody></table><p>Auteur : Abdelhalim Talbi</p></html>'
        return HTMLResponse(body,headers={**HEADERS,'Content-Security-Policy':"default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"})
    app.add_api_route('/operations/qualification-history/trends',page,methods=['GET'],include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history/trends.json',export,methods=['GET'],include_in_schema=False)
    return page
