"""V220.2 real ASGI HTTP integration (synthetic audit). Author: Abdelhalim Talbi."""
import re
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_campaign_dashboard_portal_v2197 import attach_campaign_dashboard
from odmm_campaign_dashboard_ui_v2198 import csp_policy
from test_odmm_directory_audit_v2195 import run, inputs
from odmm_ldap_membership_v2192 import _hash

@pytest.fixture
def client(tmp_path):
    run(tmp_path)
    app=FastAPI()
    attach_campaign_dashboard(app,authorize=lambda req:req.headers.get('x-test-authorization')=='approved',audit_path=tmp_path/'audit.db',anchor_path=tmp_path/'anchor.db')
    return TestClient(app)

def test_real_http_page_and_export(client):
    h={'x-test-authorization':'approved'}
    page=client.get('/operations/campaign-audit',headers=h)
    assert page.status_code==200 and 'text/html' in page.headers['content-type']
    assert page.headers['cache-control']=='no-store'
    assert page.headers['x-frame-options']=='DENY'
    assert page.headers['content-security-policy']==csp_policy(page.text)
    assert "'unsafe-inline'" not in page.headers['content-security-policy'].split('style-src')[0]
    assert 'id="identity"' in page.text and 'id="severity"' in page.text and 'id="status"' in page.text
    assert 'data-severity="ok"' in page.text and 'data-mismatch="false"' in page.text
    report=client.get('/api/v1/operations/campaign-audit/export',headers=h)
    assert report.status_code==200
    assert report.json()['case_count']==1 and report.json()['cutover_authorized'] is False
    assert report.headers['cache-control']=='no-store'

def test_http_authorization_and_query_validation(client):
    for route in ('/operations/campaign-audit','/api/v1/operations/campaign-audit/export'):
        assert client.get(route).status_code==403
        assert client.get(route,headers={'x-test-authorization':'approved'},params={'identity':'\n'}).status_code==422
        assert client.get(route,headers={'x-test-authorization':'approved'},params={'identity':'a'*257}).status_code==422
        assert client.get(route,headers={'x-test-authorization':'approved'},params={'identity':'absent'}).status_code==200
    h={'x-test-authorization':'approved'}
    assert client.get('/api/v1/operations/campaign-audit/export',headers=h,params={'identity':'absent'}).json()['case_count']==0
    assert client.get('/api/v1/operations/campaign-audit/export',headers=h,params={'mismatches':True}).json()['case_count']==0

def test_http_mismatch_filter(tmp_path):
    d,c=inputs();d['report']['resolved_members']['cn=g,dc=x']=[];d['sha256']=_hash(d['report'])
    run(tmp_path,d,c)
    app=FastAPI()
    attach_campaign_dashboard(app,authorize=lambda r:True,audit_path=tmp_path/'audit.db',anchor_path=tmp_path/'anchor.db')
    client=TestClient(app)
    r=client.get('/api/v1/operations/campaign-audit/export',params={'mismatches':True})
    assert r.status_code==200 and r.json()['mismatch_count']==1
    assert 'data-severity="warning"' in client.get('/operations/campaign-audit').text

def test_http_fail_closed_anchor_removed(tmp_path):
    run(tmp_path)
    app=FastAPI()
    attach_campaign_dashboard(app,authorize=lambda r:True,audit_path=tmp_path/'audit.db',anchor_path=tmp_path/'anchor.db')
    (tmp_path/'anchor.db').unlink()
    client=TestClient(app)
    for route in ('/operations/campaign-audit','/api/v1/operations/campaign-audit/export'):
        response=client.get(route)
        assert response.status_code==503 and response.json()=={'detail':'AUDIT_UNAVAILABLE'}
        assert str(tmp_path) not in response.text
