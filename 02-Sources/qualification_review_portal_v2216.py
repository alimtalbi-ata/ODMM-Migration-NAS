"""Authenticated, role-gated human review routes; never authorize migration.
Author: Abdelhalim Talbi.
"""
import html
import json
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from qualification_dossier_v2214 import dossier
from qualification_decisions_v2215 import append_review, review_status
from qualification_portal_v2206 import HEADERS
from qualification_review_security_v2217 import browser_write_guard
from qualification_review_gate_v2218 import enforce_review_gate
from qualification_review_http_v2222 import parse_request_id, append_http_review
from qualification_review_resilience_v2224 import map_review_storage_error
import sqlite3


def attach_review_portal(app, *, authenticate, db_path, review_db_path, required_checks, secret, thresholds=None, trusted_origins=None, anchor_path=None, strict_approval=False):
    if not callable(authenticate) or not db_path or not review_db_path or not required_checks or not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError('INVALID_REVIEW_PORTAL_CONFIG')
    checks = tuple(required_checks)
    if any(not isinstance(c, str) or not c.strip() for c in checks) or len(set(checks)) != len(checks):
        raise ValueError('INVALID_REQUIRED_CHECKS')

    def principal(request, write=False):
        identity = authenticate(request)
        if not isinstance(identity, dict) or not isinstance(identity.get('subject'), str) or not identity['subject'].strip():
            raise HTTPException(403, 'AUTHENTICATION_REQUIRED')
        roles = identity.get('roles')
        if not isinstance(roles, (list, tuple, set)) or (('qualification:write' if write else 'qualification:read') not in roles):
            raise HTTPException(403, 'INSUFFICIENT_ROLE')
        return identity['subject'].strip()

    def snapshot():
        return dossier(db_path, required_checks=checks, thresholds=thresholds)

    async def status(request: Request):
        principal(request)
        return JSONResponse(review_status(review_db_path, snapshot(), secret=secret), headers={**HEADERS, 'Cache-Control': 'no-store'})

    async def page(request: Request):
        principal(request)
        result = review_status(review_db_path, snapshot(), secret=secret)
        esc = lambda x: html.escape(str(x), quote=True)
        rows = ''.join('<tr><td>'+esc(e['seq'])+'</td><td>'+esc(e['action'])+'</td><td>'+esc(e['reviewer'])+'</td><td>'+esc(e['reason'])+'</td></tr>' for e in result['events'])
        body = '<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM · Revue</title><h1>Historique des revues</h1><p>Lecture seule · Aucun cutover autorisé</p><p>'+esc(result['review_status'])+'</p><table><thead><tr><th>#</th><th>Décision</th><th>Compte</th><th>Motif</th></tr></thead><tbody>'+rows+'</tbody></table><p>Auteur : Abdelhalim Talbi</p></html>'
        return HTMLResponse(body, headers={**HEADERS, 'Cache-Control': 'no-store'})

    async def decide(request: Request):
        subject = principal(request, write=True)
        if strict_approval:
            subject = enforce_review_gate(authenticate(request), review_db_path=review_db_path, anchor_path=anchor_path, secret=secret)
        if trusted_origins is not None:
            browser_write_guard(request, trusted_origins=trusted_origins)
        try:
            raw = await request.body()
            if len(raw) > 4096:
                raise ValueError('PAYLOAD_TOO_LARGE')
            payload = json.loads(raw)
            if not isinstance(payload, dict) or set(payload) != {'action', 'reason', 'dossier_sha256'}:
                raise ValueError('INVALID_PAYLOAD')
            current = snapshot()
            if payload['dossier_sha256'] != current['payload_sha256']:
                raise HTTPException(409, 'STALE_DOSSIER')
            request_id = parse_request_id(request)
            event = append_http_review(review_db_path, anchor_path, current,
                                       identity=authenticate(request), action=payload['action'],
                                       reason=payload['reason'], secret=secret,
                                       request_id=request_id, strict=strict_approval)
            return JSONResponse(event, headers={**HEADERS, 'Cache-Control': 'no-store'})
        except ValueError as exc:
            code = str(exc)
            if code == 'REQUEST_ID_REUSED_WITH_DIFFERENT_PAYLOAD':
                raise HTTPException(409, 'IDEMPOTENCY_CONFLICT') from exc
            if code in ('ALREADY_APPROVED', 'NO_ACTIVE_APPROVAL', 'REVOKE_BEFORE_REJECT'):
                raise HTTPException(409, 'REVIEW_STATE_CONFLICT') from exc
            if code == 'REVIEW_CHAIN_INTEGRITY_FAILURE':
                raise HTTPException(503, 'REVIEW_INTEGRITY_UNVERIFIED') from exc
            raise HTTPException(400, 'INVALID_REVIEW_REQUEST') from exc
        except (TypeError, KeyError) as exc:
            raise HTTPException(400, 'INVALID_REVIEW_REQUEST') from exc
        except (sqlite3.Error, OSError) as exc:
            raise map_review_storage_error(exc) from exc

    app.add_api_route('/operations/qualification-history/reviews', page, methods=['GET'], include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history/reviews', status, methods=['GET'], include_in_schema=False)
    app.add_api_route('/api/v1/operations/qualification-history/reviews', decide, methods=['POST'], include_in_schema=False)
    return status
