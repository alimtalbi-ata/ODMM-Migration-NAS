"""Read-only human review dossier for ODMM qualification. Author: Abdelhalim Talbi."""
import hashlib
import html
import json
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from qualification_coverage_v2213 import coverage_report
from qualification_portal_v2206 import HEADERS


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')


def dossier(db_path, *, required_checks, limit=30, thresholds=None):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('INVALID_LIMIT')
    coverage = coverage_report(db_path, required_checks=required_checks, limit=limit, thresholds=thresholds)
    # Snapshot is content-addressed, not signed. A reviewer must authenticate it separately.
    payload = {'schema': 'odmm.qualification.dossier.v2214', 'coverage': coverage,
               'review': {'decision': 'PENDING_HUMAN_REVIEW', 'approved_by': None,
                          'approved_at': None, 'required_actions': sorted(set(
                              ['REVIEW_EVIDENCE', 'VALIDATE_WINDOWS_AND_NAS_ON_REAL_SYSTEMS'] +
                              (['RESOLVE_MISSING_EVIDENCE'] if coverage['missing_evidence'] else []) +
                              (['RESOLVE_FAILED_CHECKS'] if coverage['failed_required'] else [])))},
               'read_only': True, 'cutover_authorized': False,
               'windows_qualified': False, 'nas_qualified': False}
    return {'payload': payload, 'payload_sha256': hashlib.sha256(canonical_bytes(payload)).hexdigest(),
            'digest_algorithm': 'SHA-256', 'signature_verified': False}


def verify_dossier(record):
    if not isinstance(record, dict) or set(record) != {'payload', 'payload_sha256', 'digest_algorithm', 'signature_verified'}:
        return False
    if record['digest_algorithm'] != 'SHA-256' or record['signature_verified'] is not False:
        return False
    try:
        p = record['payload']
        if p['cutover_authorized'] is not False or p['review']['decision'] != 'PENDING_HUMAN_REVIEW':
            return False
        return hashlib.sha256(canonical_bytes(p)).hexdigest() == record['payload_sha256']
    except (KeyError, TypeError, ValueError):
        return False


def render_dossier_html(record):
    if not verify_dossier(record):
        raise ValueError('INVALID_DOSSIER')
    e = lambda v: html.escape(str(v), quote=True)
    p = record['payload']; cov = p['coverage']
    rows = ''.join('<tr><td>'+e(c['check'])+'</td><td>'+e(c['state'])+'</td><td>'+e(c['severity'])+'</td></tr>' for c in cov['required'])
    return ('<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM · Dossier de recette</title>'
            '<h1>Dossier de recette — revue humaine</h1><p>Non certifié Windows/NAS · Aucun cutover autorisé</p>'
            '<p>Couverture : '+e(cov['coverage_percent'])+' %</p><p>Décision : '+e(p['review']['decision'])+'</p>'
            '<p>Actions : '+e(', '.join(p['review']['required_actions']))+'</p>'
            '<table><thead><tr><th>Contrôle</th><th>État</th><th>Criticité</th></tr></thead><tbody>'+rows+'</tbody></table>'
            '<p>Empreinte SHA-256 (intégrité, pas authentification) : <code>'+e(record['payload_sha256'])+'</code></p>'
            '<p>Auteur : Abdelhalim Talbi</p></html>')


def attach_qualification_dossier(app, *, authorize, db_path, required_checks, thresholds=None):
    if not callable(authorize) or not hasattr(app, 'add_api_route') or not db_path:
        raise ValueError('AUTHORIZATION_AND_APP_AND_DB_REQUIRED')
    # Fail early on invalid mandatory check configuration, without reading the DB.
    if not isinstance(required_checks, (list, tuple)) or not required_checks or len(required_checks) > 200 or any(type(c) is not str or not c.strip() or len(c)>128 for c in required_checks) or len(set(required_checks)) != len(required_checks):
        raise ValueError('INVALID_REQUIRED_CHECKS')
    checks = tuple(required_checks)
    def guarded(request, limit):
        if authorize(request) is not True:
            raise HTTPException(403, 'FORBIDDEN')
        return dossier(db_path, required_checks=checks, limit=limit, thresholds=thresholds)
    async def page(request: Request, limit: int = 30):
        return HTMLResponse(render_dossier_html(guarded(request, limit)), headers=HEADERS)
    async def export(request: Request, limit: int = 30):
        return JSONResponse(guarded(request, limit), headers=HEADERS)
    app.add_api_route('/operations/qualification-history/dossier', page, methods=['GET'], include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history/dossier.json', export, methods=['GET'], include_in_schema=False)
    return page
