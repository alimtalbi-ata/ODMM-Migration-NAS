import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_oidc_audit_v2110 import OperationsAudit,create_audited_oidc_operations_app
from test_odmm_oidc_boundary_v2107 import keys,signed
from test_odmm_vault_observability_v2104 import Fake

@pytest.fixture
def app_and_audit(monkeypatch,keys):
    import odmm_vault_readiness_v2100 as upstream
    monkeypatch.setattr(upstream,'create_vault_operations_app',lambda **kw:FastAPI())
    audit=OperationsAudit(capacity=5)
    app=create_audited_oidc_operations_app(issuer='https://idp.example.org',
        audience='odmm-operations',jwks_provider=lambda:keys[1],ha_client=Fake(),
        audit=audit,allowed_roles={'viewer'},revocation_check=lambda j,s:False)
    return app,audit

def test_audit_bounded_and_copy():
    audit=OperationsAudit(2)
    for _ in range(3): audit.record(outcome='DENY',reason='IDENTITY_REJECTED')
    assert len(audit.snapshot())==2
    audit.snapshot()[0]['reason']='secret'
    assert audit.snapshot()[0]['reason']=='IDENTITY_REJECTED'
    for bad in (0,-1,10001,True):
        with pytest.raises(ValueError):OperationsAudit(bad)

def test_http_routes_fail_closed_and_redaction(app_and_audit,keys):
    app,audit=app_and_audit
    routes=['/api/v1/operations/vault/ha-health','/operations/vault/ha-health',
            '/api/v1/operations/vault/ha-metrics']
    with TestClient(app) as client:
        for route in routes:
            for headers in ({},{'Authorization':'Bearer secret-value'},
                            {'Authorization':'Bearer '+signed(keys,jti='revoked',odmm_roles=['admin'])}):
                r=client.get(route,headers=headers)
                assert r.status_code==403
                assert 'secret-value' not in r.text
            r=client.get(route,headers={'Authorization':'Bearer '+signed(keys,jti='good')})
            assert r.status_code==200
            assert r.headers['cache-control']=='no-store'
    entries=audit.snapshot()
    assert entries[-1]['outcome']=='ALLOW'
    assert any(e['outcome']=='DENY' for e in entries)
    assert all(set(e)=={'schema','timestamp','outcome','reason'} for e in entries)
    assert 'secret-value' not in str(entries)

def test_idp_outage_and_revocation_denies(monkeypatch,keys):
    import odmm_vault_readiness_v2100 as upstream
    monkeypatch.setattr(upstream,'create_vault_operations_app',lambda **kw:FastAPI())
    for jwks,revocation in [(lambda: (_ for _ in ()).throw(TimeoutError('idp-secret')),lambda j,s:False),
                            (lambda:keys[1],lambda j,s: (_ for _ in ()).throw(TimeoutError('revocation-secret')))]:
        audit=OperationsAudit()
        app=create_audited_oidc_operations_app(issuer='https://idp.example.org',audience='odmm-operations',
            jwks_provider=jwks,ha_client=Fake(),audit=audit,revocation_check=revocation)
        with TestClient(app) as client:
            r=client.get('/api/v1/operations/vault/ha-health',headers={'Authorization':'Bearer '+signed(keys,jti='good')})
            assert r.status_code==403
            assert 'secret' not in r.text
        assert audit.snapshot()[-1]['outcome']=='DENY'
