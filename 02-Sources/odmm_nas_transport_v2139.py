"""Read-only vendor evidence transport contract, not a certified hardware driver.
Author: Abdelhalim Talbi.

Caller supplies a trusted TLS-pinned GET transport; no outbound network is opened here.
"""
import hashlib
import json
from collections.abc import Mapping
from urllib.parse import urlsplit

VENDOR_ROUTES = {
    'netapp_ontap': '/api/storage/volumes',
    'pure_flashblade': '/api/2.0/file-systems',
    'dell_onefs': '/platform/16/protocols',
}


def make_vendor_reader(*, vendor, base_url, transport, max_bytes=1048576):
    """transport(url, *, max_bytes, redirects=False, tls_verify=True) -> bytes.
    Route paths are illustrative discovery candidates; hardware API validation pending.
    """
    if vendor not in VENDOR_ROUTES or not callable(transport):
        raise ValueError('INVALID_VENDOR_OR_TRANSPORT')
    if type(base_url) is not str:
        raise ValueError('INVALID_BASE_URL')
    p = urlsplit(base_url)
    if (p.scheme != 'https' or not p.hostname or p.username is not None or
        p.password is not None or p.query or p.fragment or p.path not in ('','/') or
        p.port is None or p.hostname.lower() in ('localhost','localhost.localdomain') or
        not p.hostname.isascii() or not (1 <= p.port <= 65535)):
        raise ValueError('INVALID_BASE_URL')
    if type(max_bytes) is not int or not (1024 <= max_bytes <= 2_000_000):
        raise ValueError('INVALID_MAX_BYTES')
    url = f'https://{p.hostname}:{p.port}{VENDOR_ROUTES[vendor]}'
    def read():
        try:
            data = transport(url, max_bytes=max_bytes, redirects=False, tls_verify=True)
            if type(data) is not bytes or len(data) > max_bytes:
                raise ValueError('INVALID_RESPONSE_SIZE')
            decoded = json.loads(data)
            if type(decoded) is not dict:
                raise ValueError('INVALID_RESPONSE')
            if any(k in decoded for k in ('password','secret','token','access_token')):
                raise ValueError('SECRET_BEARING_RESPONSE')
            return {'vendor':vendor, 'route':VENDOR_ROUTES[vendor],
                    'raw_sha256':hashlib.sha256(data).hexdigest(),
                    'data':decoded, 'certified':False, 'cutover_authorized':False,
                    'blockers':['API_SCHEMA_NOT_VENDOR_QUALIFIED','TRANSPORT_NOT_INDEPENDENTLY_ATTESTED',
                                'ACL_EFFECTIVE_ACCESS_NOT_PROVEN']}
        except Exception as exc:
            raise ValueError('VENDOR_READ_FAILED') from exc
    return read


def attach_nas_access_dashboard(app, *, authorize, providers):
    """Authenticated HTML dashboard for the existing V213.8 access evidence providers."""
    from fastapi import Request
    from fastapi.responses import HTMLResponse
    from html import escape
    from odmm_nas_probe_adapters_v2138 import compare_collected_evidence
    if not callable(authorize) or type(providers) is not dict or set(providers) != set(VENDOR_ROUTES) or not all(callable(v) for v in providers.values()):
        raise ValueError('AUTH_AND_PROVIDERS_REQUIRED')
    @app.get('/operations/nas-access', response_class=HTMLResponse)
    def dashboard(request:Request):
        headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
                 'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"}
        try: allowed = authorize(request) is True
        except Exception: allowed = False
        if not allowed:
            return HTMLResponse('Access denied',status_code=403,headers=headers)
        rows=[]
        vendors=tuple(VENDOR_ROUTES)
        for source in vendors:
            for target in vendors:
                if source==target: continue
                try:
                    result=compare_collected_evidence(providers[source](),providers[target]())
                    rows.append(f'<tr><td>{escape(source)}</td><td>{escape(target)}</td><td>{result["checked"]}</td><td>{len(result["discrepancies"])}</td><td>BLOCKED</td></tr>')
                except Exception:
                    rows.append(f'<tr><td>{escape(source)}</td><td>{escape(target)}</td><td>—</td><td>—</td><td>UNAVAILABLE</td></tr>')
        html='<!doctype html><html lang="fr"><meta charset="utf-8"><title>ODMM NAS Access Audit</title><style>body{font:16px system-ui;background:#101b2b;color:#edf3fa;padding:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #456;padding:.75rem;text-align:left}th{background:#234}</style><h1>ODMM — Audit des accès NAS</h1><p>Lecture seule · aucune bascule autorisée · Auteur : Abdelhalim Talbi</p><table><thead><tr><th>Source</th><th>Cible</th><th>Sondes</th><th>Écarts</th><th>Statut</th></tr></thead><tbody>'+''.join(rows)+'</tbody></table></html>'
        return HTMLResponse(html,headers=headers)
