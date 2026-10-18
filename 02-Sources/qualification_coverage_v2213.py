"""Evidence coverage advisory gate for ODMM qualification history.
Author: Abdelhalim Talbi. Read-only, never authorizes cutover.
"""
import html
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from qualification_committee_v2212 import committee_report
from qualification_portal_v2206 import HEADERS


def coverage_report(db_path, *, required_checks, limit=30, thresholds=None):
    if not isinstance(required_checks, (list, tuple)) or not required_checks or len(required_checks) > 200 or any(not isinstance(x, str) or not x.strip() or len(x)>128 for x in required_checks) or len(set(required_checks)) != len(required_checks):
        raise ValueError('INVALID_REQUIRED_CHECKS')
    base = committee_report(db_path, limit=limit, thresholds=thresholds)
    controls = {c['check']: c for c in base['controls']}
    required = []
    for name in required_checks:
        control = controls.get(name)
        state = control['latest'] if control else 'MISSING'
        required.append({'check':name,'state':state,'covered':state=='PASS', 'evidence_missing':state in ('MISSING','NOT_EXECUTED'), 'severity':control['severity'] if control else 'UNCLASSIFIED'})
    covered = sum(c['covered'] for c in required)
    missing = [c['check'] for c in required if c['evidence_missing']]
    failed = [c['check'] for c in required if c['state']=='FAIL']
    violations = list(base['violations'])
    if missing: violations.append('MANDATORY_EVIDENCE_MISSING')
    if failed: violations.append('MANDATORY_CHECK_FAILED')
    return {'schema':'odmm.qualification.coverage.v2213', 'required':required, 'required_total':len(required), 'required_passed':covered, 'coverage_percent':round(100*covered/len(required),2), 'missing_evidence':missing, 'failed_required':failed, 'violations':violations, 'quality_gate':'REVIEW_REQUIRED' if violations else 'METRICS_WITHIN_THRESHOLDS', 'summary':base['summary'], 'read_only':True,'windows_qualified':False,'nas_qualified':False,'cutover_authorized':False,'human_approval_required':True}


def render_coverage_html(report):
    e=lambda x:html.escape(str(x),quote=True)
    rows=''.join('<tr><td>'+e(c['check'])+'</td><td>'+e(c['state'])+'</td><td>'+e(c['severity'])+'</td></tr>' for c in report['required'])
    return ('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM · Couverture de recette</title><h1>Couverture des contrôles obligatoires</h1><p>Lecture seule · Aucun cutover automatique · Non certifié Windows/NAS</p><p>Couverture : '+e(report['coverage_percent'])+' % ('+e(report['required_passed'])+'/'+e(report['required_total'])+')</p><p>Écarts : '+e(', '.join(report['violations']) or 'Aucun')+'</p><table><thead><tr><th>Contrôle</th><th>État</th><th>Criticité</th></tr></thead><tbody>'+rows+'</tbody></table><p>Auteur : Abdelhalim Talbi</p></html>')


def attach_qualification_coverage(app, *, authorize, db_path, required_checks, thresholds=None):
    if not callable(authorize) or not hasattr(app,'add_api_route') or not db_path:
        raise ValueError('AUTHORIZATION_AND_APP_AND_DB_REQUIRED')
    # Validate configuration before routes are published.
    if not isinstance(required_checks,(list,tuple)) or not required_checks or len(required_checks)>200 or any(not isinstance(x,str) or not x.strip() or len(x)>128 for x in required_checks) or len(set(required_checks))!=len(required_checks):
        raise ValueError('INVALID_REQUIRED_CHECKS')
    checks=tuple(required_checks)
    def guarded(request,limit):
        if authorize(request) is not True: raise HTTPException(403,'FORBIDDEN')
        return coverage_report(db_path,required_checks=checks,limit=limit,thresholds=thresholds)
    async def page(request:Request,limit:int=30):
        return HTMLResponse(render_coverage_html(guarded(request,limit)),headers={**HEADERS,'Content-Security-Policy':"default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"})
    async def export(request:Request,limit:int=30):
        return JSONResponse(guarded(request,limit),headers=HEADERS)
    app.add_api_route('/operations/qualification-history/coverage',page,methods=['GET'],include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history/coverage.json',export,methods=['GET'],include_in_schema=False)
    return page
