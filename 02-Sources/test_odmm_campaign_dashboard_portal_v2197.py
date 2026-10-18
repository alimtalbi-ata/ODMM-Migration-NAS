import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_campaign_dashboard_portal_v2197 import attach_campaign_dashboard
from odmm_operations_portal import PAGE

def test_navigation_present():
    assert '/operations/campaign-audit' in PAGE
    assert '/api/v1/operations/campaign-audit/export' in PAGE

def test_auth_required(tmp_path):
    app=FastAPI();attach_campaign_dashboard(app,authorize=lambda r:False,audit_path=tmp_path/'x',anchor_path=tmp_path/'y')
    client=TestClient(app)
    assert client.get('/operations/campaign-audit').status_code==403
    assert client.get('/api/v1/operations/campaign-audit/export').status_code==403

def test_fail_closed(tmp_path):
    app=FastAPI();attach_campaign_dashboard(app,authorize=lambda r:True,audit_path=tmp_path/'x',anchor_path=tmp_path/'y')
    client=TestClient(app)
    assert client.get('/operations/campaign-audit').status_code==503
    assert client.get('/api/v1/operations/campaign-audit/export').status_code==503
    assert client.get('/operations/campaign-audit?identity=%0A').status_code==422

def test_requires_auth_callback():
    with pytest.raises(ValueError):attach_campaign_dashboard(FastAPI(),authorize=None,audit_path='x',anchor_path='y')
