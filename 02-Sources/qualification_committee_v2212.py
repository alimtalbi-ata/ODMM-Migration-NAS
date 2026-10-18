"""Fail-closed, read-only committee report for qualification history.
Author: Abdelhalim Talbi. Advisory metrics, never a cutover approval.
"""
import html
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from qualification_trends_v2211 import trends
from qualification_portal_v2206 import HEADERS

DEFAULT_THRESHOLDS = {'max_open_failures': 0, 'max_regressions': 0, 'min_runs': 3}

def committee_report(db_path, *, limit=30, thresholds=None):
    limits = DEFAULT_THRESHOLDS if thresholds is None else thresholds
    if not isinstance(limits, dict) or set(limits) != set(DEFAULT_THRESHOLDS) or any(type(v) is not int or v < 0 or v > 100 for v in limits.values()) or limits['min_runs'] < 2:
        raise ValueError('INVALID_THRESHOLDS')
    data = trends(db_path, limit)
    controls = data['controls']
    summary = data.get('summary', {'runs': 0, 'regressions': 0, 'improvements': 0, 'open_failures': 0})
    violations = [name for name, observed, bound in (
        ('INSUFFICIENT_RUNS', summary['runs'], limits['min_runs']),
    ) if observed < bound]
    if summary['open_failures'] > limits['max_open_failures']:
        violations.append('OPEN_FAILURES_EXCEEDED')
    if summary['regressions'] > limits['max_regressions']:
        violations.append('REGRESSIONS_EXCEEDED')
    if any(c['latest'] == 'NOT_EXECUTED' for c in controls):
        violations.append('CONTROLS_NOT_EXECUTED')
    return {'schema': 'odmm.qualification.committee.v2212', 'summary': summary,
            'thresholds': dict(limits), 'violations': violations,
            'quality_gate': 'REVIEW_REQUIRED' if violations else 'METRICS_WITHIN_THRESHOLDS',
            'controls': controls, 'runs': data['runs'],
            'read_only': True, 'windows_qualified': False, 'nas_qualified': False,
            'cutover_authorized': False, 'human_approval_required': True}

def render_committee_html(report):
    esc = lambda value: html.escape(str(value), quote=True)
    rows = []
    for control in report['controls']:
        states = control['states']
        visual = ''.join('●' if state == 'PASS' else '✕' if state == 'FAIL' else '○' for state in states)
        rows.append('<tr><td>'+esc(control['check'])+'</td><td>'+esc(control['severity'])+'</td><td>'+esc(visual)+'</td><td>'+esc(control['latest'])+'</td><td>'+str(control['regressions'])+'</td></tr>')
    return ('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM · Comité de recette</title>'
            '<h1>Qualification · comité de recette</h1><p>Indicateurs consultatifs, pas de certification Windows/NAS, cutover interdit.</p>'
            '<p>État : '+esc(report['quality_gate'])+'</p><p>Exécutions : '+str(report['summary']['runs'])+'</p>'
            '<p>Écarts : '+esc(', '.join(report['violations']) or 'Aucun seuil dépassé')+'</p>'
            '<table><thead><tr><th>Contrôle</th><th>Criticité indicative</th><th>Évolution (ancien → récent)</th><th>Dernier état</th><th>Régressions</th></tr></thead><tbody>'
            +''.join(rows)+'</tbody></table><p>Légende : ● PASS, ✕ FAIL, ○ NOT_EXECUTED</p>'
            '<p>Auteur : Abdelhalim Talbi</p></html>')

def attach_qualification_committee(app, *, authorize, db_path, thresholds=None):
    if not callable(authorize) or not hasattr(app, 'add_api_route') or not db_path:
        raise ValueError('AUTHORIZATION_AND_APP_AND_DB_REQUIRED')
    # Validate configuration before registering routes.
    limits = DEFAULT_THRESHOLDS if thresholds is None else thresholds
    if not isinstance(limits, dict) or set(limits) != set(DEFAULT_THRESHOLDS) or any(type(v) is not int or v < 0 or v > 100 for v in limits.values()) or limits['min_runs'] < 2:
        raise ValueError('INVALID_THRESHOLDS')
    def guarded(request, limit):
        if authorize(request) is not True:
            raise HTTPException(403, 'FORBIDDEN')
        return committee_report(db_path, limit=limit, thresholds=limits)
    async def export(request: Request, limit: int = 30):
        return JSONResponse(guarded(request, limit), headers=HEADERS)
    async def page(request: Request, limit: int = 30):
        return HTMLResponse(render_committee_html(guarded(request, limit)), headers={**HEADERS, 'Content-Security-Policy': "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"})
    app.add_api_route('/operations/qualification-history/committee', page, methods=['GET'], include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history/committee.json', export, methods=['GET'], include_in_schema=False)
    return page
