from fastapi.testclient import TestClient
from odmm_operations_app import create_netapp_full_operations_app
from odmm_operations_security import Principal
from test_odmm_netapp_cockpit_v2085 import evidence


def build(tmp_path, permitted=True, provider=evidence):
    def identity(request):
        return Principal('test',frozenset({'viewer'}),verified=permitted)
    import sqlite3
    sqlite3.connect(str(tmp_path/'registry.sqlite')).close()
    return TestClient(create_netapp_full_operations_app(
        registry_path=str(tmp_path/'registry.sqlite'),resolve_verified_principal=identity,
        get_netapp_inventories=lambda: ({},{}),get_netapp_differences=provider))

def test_single_portal_links(tmp_path):
    r=build(tmp_path).get('/operations')
    assert r.status_code==200
    assert 'href="/operations/netapp"' in r.text
    assert 'href="/operations/netapp/differences"' in r.text
    assert 'script-src' in r.headers['content-security-policy']

def test_differences_mounted(tmp_path):
    c=build(tmp_path)
    assert c.get('/operations/netapp/differences').status_code==200
    assert c.get('/api/v1/operations/netapp/differences').json()['cutover_authorized'] is False

def test_shared_auth_blocks_every_netapp_route(tmp_path):
    c=build(tmp_path,False)
    for route in ('/operations','/operations/netapp','/api/v1/operations/netapp/preflight','/operations/netapp/differences','/api/v1/operations/netapp/differences'):
        assert c.get(route).status_code==403,route

def test_provider_failure_is_private(tmp_path):
    def fail():raise RuntimeError('SECRET_PRIVATE')
    r=build(tmp_path,provider=fail).get('/api/v1/operations/netapp/differences')
    assert r.status_code==503 and 'SECRET_PRIVATE' not in r.text

def test_no_write_routes(tmp_path):
    c=build(tmp_path)
    for route in ('/operations/netapp','/operations/netapp/differences','/api/v1/operations/netapp/differences'):
        assert c.post(route).status_code==405

def test_missing_provider_rejected(tmp_path):
    import pytest
    with pytest.raises(ValueError,match='NETAPP_SERVER_PROVIDERS_REQUIRED'):
        create_netapp_full_operations_app(registry_path=str(tmp_path/'db'),resolve_verified_principal=lambda _:None,get_netapp_inventories=None,get_netapp_differences=evidence)
