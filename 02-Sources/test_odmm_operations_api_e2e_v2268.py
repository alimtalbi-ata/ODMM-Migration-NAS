"""Actual HTTP contract tests: FastAPI TestClient + real SQLite registry."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from registry import Registry
from odmm_operations_api import attach_readonly_routes
from odmm_registry_client_v2267 import normalize_registry_jobs

@pytest.fixture
def service(tmp_path):
    path=tmp_path/'registry.sqlite'
    with Registry(path) as reg:
        job=reg.create_job('/source','/target')
        reg.enqueue(job,'op-1',{'mode':'dry_run'})
    app=FastAPI()
    attach_readonly_routes(app,registry_path=path,authorize=lambda req: req.headers.get('authorization') == 'Bearer test-secret')
    return TestClient(app),path,job

def test_authenticated_contract_real_sqlite(service):
    client,path,job=service
    response=client.get('/api/v1/operations/jobs',headers={'Authorization':'Bearer test-secret'})
    assert response.status_code==200
    items=normalize_registry_jobs(response.json())
    assert len(items)==1 and items[0]['id']==job and items[0]['progress_percent'] is None
    assert client.get('/api/v1/operations/overview',headers={'Authorization':'Bearer test-secret'}).json()['jobs']==1

def test_missing_or_wrong_bearer_forbidden(service):
    client,_,_=service
    assert client.get('/api/v1/operations/jobs').status_code==403
    assert client.get('/api/v1/operations/jobs',headers={'Authorization':'Bearer wrong'}).status_code==403

def test_bad_limit_and_missing_job(service):
    client,_,_=service
    h={'Authorization':'Bearer test-secret'}
    assert client.get('/api/v1/operations/jobs?limit=201',headers=h).status_code==400
    assert client.get('/api/v1/operations/jobs/absent/operations',headers=h).status_code==404
    assert client.get('/api/v1/operations/jobs?limit=abc',headers=h).status_code==422

def test_read_only_http_requests_do_not_mutate_registry(service):
    client,path,job=service
    before=path.read_bytes()
    h={'Authorization':'Bearer test-secret'}
    for endpoint in ('/api/v1/operations/jobs','/api/v1/operations/overview',f'/api/v1/operations/jobs/{job}/operations'):
        assert client.get(endpoint,headers=h).status_code==200
    assert path.read_bytes()==before
    assert client.post('/api/v1/operations/jobs',headers=h).status_code==405

def test_authorizer_required(tmp_path):
    with pytest.raises(ValueError,match='AUTHORIZATION_PROVIDER_REQUIRED'):
        attach_readonly_routes(FastAPI(),registry_path=tmp_path/'missing',authorize=None)
