import asyncio
from types import SimpleNamespace
import httpx
from fastapi import FastAPI
from qualification_oidc_recovery_http_v2245 import attach_custody_diagnostic

STATE={'generation':2,'jwks_sha256':'a'*64}


def client_result(app, headers=None):
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as c:
            return await c.get('/api/v1/security/oidc/custody-diagnostic',headers=headers)
    return asyncio.run(run())


def build(monkeypatch, identity):
    import qualification_oidc_recovery_http_v2245 as mod
    monkeypatch.setattr(mod, 'inspect_handoff', lambda **kw: {'state':'PENDING_CUSTODY_ACK','authentication_allowed':False})
    app=FastAPI()
    rotation=SimpleNamespace(rotation=SimpleNamespace(state=STATE))
    attach_custody_diagnostic(app,authenticate=lambda r:identity,rotation=rotation,
        ledger_path='db',witness_path='witness',witness_secret=b'a'*32,custody_secret=b'b'*32)
    return app


def test_read_only_pending(monkeypatch):
    app=build(monkeypatch,{'subject':'operator','roles':['qualification:read']})
    r=client_result(app)
    assert r.status_code==200 and r.json()['authentication_allowed'] is False
    assert r.headers['cache-control']=='no-store'
    assert client_result(app).status_code==200
    assert not any('POST' in getattr(route,'methods',set()) and 'custody-diagnostic' in route.path for route in app.routes)


def test_role_denied(monkeypatch):
    assert client_result(build(monkeypatch,{'subject':'user','roles':['qualification:write']})).status_code==403


def test_invalid_evidence_returns_503(monkeypatch):
    import qualification_oidc_recovery_http_v2245 as mod
    app=build(monkeypatch,{'subject':'operator','roles':['qualification:read']})
    def fail(**kw): raise ValueError('PRIVATE_FILE_PATH')
    monkeypatch.setattr(mod,'inspect_handoff',fail)
    r=client_result(app)
    assert r.status_code==503 and 'PRIVATE_FILE_PATH' not in r.text


def test_duplicate_route_rejected(monkeypatch):
    import pytest
    app=build(monkeypatch,{'subject':'operator','roles':['qualification:read']})
    with pytest.raises(ValueError,match='DUPLICATE'):
        attach_custody_diagnostic(app,authenticate=lambda r:{},rotation=SimpleNamespace(rotation=SimpleNamespace(state=STATE)),ledger_path='db',witness_path='w',witness_secret=b'a'*32,custody_secret=b'b'*32)
