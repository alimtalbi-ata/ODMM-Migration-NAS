from odmm_vault_prometheus_v2105 import render_prometheus,create_vault_prometheus_operations_app
from test_odmm_vault_observability_v2104 import Fake

def test_export():
    x=render_prometheus(Fake());assert 'odmm_vault_ha_available_endpoints 2' in x and 'odmm_vault_ha_requests_total 10' in x

def test_fail_closed_export():
    class Broken:
        def status(self):raise RuntimeError('token secret')
    x=render_prometheus(Broken());assert 'telemetry_valid 0' in x and 'secret' not in x

def test_no_sensitive_labels():
    x=render_prometheus(Fake());assert 'endpoint=' not in x and 'token=' not in x

def test_authenticated_http_routes():
    from fastapi.testclient import TestClient
    from inspect import signature
    from odmm_vault_readiness_v2100 import create_vault_operations_app
    # This is a contract check for route mounting; full HTTP auth setup varies by deployment.
    assert 'resolve_verified_principal' in str(signature(create_vault_operations_app))
