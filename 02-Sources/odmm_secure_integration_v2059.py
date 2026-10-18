"""ODMM V205.9 — hardened single-route collection integration. Auteur: Abdelhalim Talbi."""
import hashlib
import hmac
import json
from urllib.parse import urlsplit

from odmm_collection_security_v2058 import SecurityGate
from odmm_collection_gate_v2061 import TransactionalSecurityGate


def csrf_for_session(session_id, secret):
    if not isinstance(session_id, str) or len(session_id) < 16 or not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError('SESSION_CSRF_CONFIGURATION_INVALID')
    return hmac.new(secret, session_id.encode(), hashlib.sha256).hexdigest()


def attach_hardened_collection(app, *, gate, identity_provider, session_provider,
                               csrf_secret, expected_origin, token_provider,
                               allow_hosts, collector=None):
    """Session identity comes only from trusted server-side providers, not request JSON."""
    from fastapi import Request, HTTPException
    from fastapi.responses import JSONResponse
    from odmm_collection_service_v2056 import collect_inventory
    from odmm_vendor_api_readonly_v2055 import CollectionError
    if not isinstance(gate, (SecurityGate, TransactionalSecurityGate)) or not callable(identity_provider) or not callable(session_provider) or not callable(token_provider):
        raise ValueError('DEPENDENCIES_REQUIRED')
    if not isinstance(expected_origin, str) or not expected_origin.startswith('https://'):
        raise ValueError('HTTPS_ORIGIN_REQUIRED')
    if not isinstance(csrf_secret, bytes) or len(csrf_secret) < 32:
        raise ValueError('CSRF_SECRET_REQUIRED')
    paths = {'/api/v1/qualification/collect', '/api/v1/qualification/collect-secure', '/api/v1/qualification/collect-hardened'}
    if any(getattr(route, 'path', None) in paths for route in app.routes):
        raise ValueError('LEGACY_COLLECTION_ROUTE_PRESENT')
    collector = collector or collect_inventory

    async def route(request: Request):
        actor, role = identity_provider(request)
        session_id = session_provider(request)
        try:
            expected_csrf = csrf_for_session(session_id, csrf_secret)
        except ValueError:
            raise HTTPException(403, 'SESSION_REQUIRED')
        header = request.headers.get('x-odmm-csrf', '')
        cookie = request.cookies.get('odmm_csrf', '')
        if not (hmac.compare_digest(header, expected_csrf) and hmac.compare_digest(cookie, expected_csrf)):
            raise HTTPException(403, 'SESSION_CSRF_DENIED')
        if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
            raise HTTPException(415, 'JSON_REQUIRED')
        # Enforce size before JSON parsing; avoid unbounded body reads.
        if request.headers.get('content-length', '').isdigit() and int(request.headers['content-length']) > 4096:
            raise HTTPException(413, 'TOO_LARGE')
        raw = await request.body()
        if len(raw) > 4096:
            raise HTTPException(413, 'TOO_LARGE')
        result = gate.check(actor=actor, role=role, origin=request.headers.get('origin', ''),
                            expected_origin=expected_origin, csrf_cookie=cookie, csrf_header=header)
        if result != 'ALLOW':
            raise HTTPException(429 if result == 'DENY_RATE' else 403, result)
        try:
            data = json.loads(raw)
            if not isinstance(data, dict) or set(data) != {'vendor', 'host'} or not all(isinstance(v, str) for v in data.values()):
                raise ValueError('INVALID_INPUT')
            report = collector(data['vendor'], data['host'], token_provider=token_provider, allow_hosts=allow_hosts)
        except (ValueError, CollectionError):
            raise HTTPException(422, 'COLLECTION_REJECTED')
        return JSONResponse(report, headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})

    app.add_api_route('/api/v1/qualification/collect-hardened', route, methods=['POST'])
    return route
