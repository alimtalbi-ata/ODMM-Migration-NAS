"""HTTP auth + RBAC end-to-end route tests with isolated upstream application."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_operations_security import Principal
from test_odmm_vault_observability_v2104 import Fake
from odmm_vault_prometheus_v2105 import create_vault_prometheus_operations_app
from odmm_vault_grafana_v2106 import dashboard

def client(monkeypatch, principal):
    import odmm_vault_readiness_v2100 as mod
    monkeypatch.setattr(mod,'create_vault_operations_app',lambda **kwargs: FastAPI())
    app=create_vault_prometheus_operations_app(ha_client=Fake(),resolve_verified_principal=lambda request: principal)
    return TestClient(app)

@pytest.mark.parametrize('url', ['/api/v1/operations/vault/ha-health','/operations/vault/ha-health','/api/v1/operations/vault/ha-metrics'])
def test_verified_operator_can_read(monkeypatch,url):
    with client(monkeypatch,Principal('operator',frozenset({'operator'}),True)) as c:
        r=c.get(url)
        assert r.status_code==200
        assert r.headers['cache-control']=='no-store'
        assert r.headers['x-content-type-options']=='nosniff'
        assert 'token' not in r.text.lower()

@pytest.mark.parametrize('principal',[None,Principal('x',frozenset({'operator'}),False),Principal('x',frozenset({'unknown'}),True),Principal('',frozenset({'admin'}),True)])
@pytest.mark.parametrize('url',['/api/v1/operations/vault/ha-health','/operations/vault/ha-health','/api/v1/operations/vault/ha-metrics'])
def test_denied(monkeypatch,principal,url):
    with client(monkeypatch,principal) as c:
        assert c.get(url).status_code==403

def test_methods_restricted(monkeypatch):
    with client(monkeypatch,Principal('a',frozenset({'admin'}),True)) as c:
        for url in ['/api/v1/operations/vault/ha-health','/operations/vault/ha-health','/api/v1/operations/vault/ha-metrics']:
            assert c.post(url).status_code==405

def test_prometheus_contract(monkeypatch):
    with client(monkeypatch,Principal('a',frozenset({'auditor'}),True)) as c:
        r=c.get('/api/v1/operations/vault/ha-metrics')
        assert 'odmm_vault_ha_telemetry_valid 1' in r.text
        assert 'text/plain' in r.headers['content-type']

def test_grafana_dashboard():
    d=dashboard()
    assert len(d['panels'])==5
    assert all(p['datasource']['type']=='prometheus' for p in d['panels'])
    assert all('token' not in p['targets'][0]['expr'] for p in d['panels'])
