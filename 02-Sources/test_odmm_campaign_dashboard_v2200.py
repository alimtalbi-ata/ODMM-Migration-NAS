"""Regression of HTTP CSP and severity filters. Author: Abdelhalim Talbi."""
import re
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_campaign_dashboard_ui_v2198 import render_hardened,csp_policy
from odmm_campaign_dashboard_portal_v2197 import attach_campaign_dashboard
from test_odmm_campaign_dashboard_ui_v2199 import report

def test_severity_rows():
    page=render_hardened(report())
    assert 'data-severity="critical"' in page
    assert 'data-severity="ok"' in page
    assert 'tr[hidden]{display:none}' in page

def test_group_warning():
    r=report();r['cases'][0]['local_access_equal']=True;r['cases'][0]['groups_equal']=False;r['cases'][0]['mismatch']=True
    assert 'data-severity="warning"' in render_hardened(r)

def test_csp_exact_hash():
    page=render_hardened(report())
    csp=csp_policy(page)
    assert "script-src 'sha256-" in csp and "'unsafe-inline'" not in csp.split('style-src')[0]
    assert 'frame-ancestors \'none\'' in csp

def test_portal_header(monkeypatch,tmp_path):
    import odmm_campaign_dashboard_portal_v2197 as portal
    monkeypatch.setattr(portal,'build_dashboard',lambda *a,**kw:report())
    app=FastAPI()
    attach_campaign_dashboard(app,authorize=lambda r:True,audit_path=tmp_path/'a',anchor_path=tmp_path/'b')
    resp=TestClient(app).get('/operations/campaign-audit')
    assert resp.status_code==200
    assert resp.headers['content-security-policy']==csp_policy(resp.text)
    assert "script-src 'sha256-" in resp.headers['content-security-policy']
    assert "script-src 'unsafe-inline'" not in resp.headers['content-security-policy']
    assert resp.headers['cache-control']=='no-store'
    assert resp.headers['x-frame-options']=='DENY'
