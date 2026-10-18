from datetime import datetime,timezone
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_probe_adapters_v2138 import collect_readonly_evidence
from odmm_nas_provenance_v2143 import wrap_provenance
from odmm_nas_provenance_portal_v2144 import attach_provenance_dashboard
import pytest

V=('netapp_ontap','pure_flashblade','dell_onefs')
NOW='2026-10-15T20:00:00Z'
def providers():
    def make(v):
        e=collect_readonly_evidence(vendor=v,firmware='test',collection_id='c',requests=[{'principal':'u','path':'/a','right':'READ'}],collector=lambda *a:{'allowed':v!='dell_onefs','method':'ACL_READONLY','identity_resolved':True})
        return wrap_provenance(evidence=e,collector_id=v+'-collector',endpoint_id=v+'-endpoint',observed_at=NOW)
    return {v:lambda v=v:make(v) for v in V}
def client(auth=True,provs=None):
    app=FastAPI(); attach_provenance_dashboard(app,authorize=lambda r:auth,providers=provs or providers(),clock=lambda:NOW)
    return TestClient(app)
def test_six_directions():
    c=client()
    for a in V:
        for b in V:
            if a!=b:
                r=c.get(f'/api/v1/operations/nas-provenance/{a}/{b}')
                assert r.status_code==200 and r.json()['cutover_authorized'] is False
    assert c.get('/operations/nas-provenance').text.count('<tr>')==7
def test_access_denied():
    c=client(False)
    assert c.get('/operations/nas-provenance').status_code==403
    assert c.get('/api/v1/operations/nas-provenance/netapp_ontap/pure_flashblade').status_code==403
def test_invalid_direction_and_filter():
    c=client()
    assert c.get('/api/v1/operations/nas-provenance/netapp_ontap/netapp_ontap').status_code==400
    assert c.get('/operations/nas-provenance?only=bad').status_code==400
def test_filters():
    c=client()
    assert c.get('/operations/nas-provenance?source=netapp_ontap').text.count('<tr>')==3
    assert c.get('/operations/nas-provenance?only=mismatch').text.count('<tr>')==5
def test_expired_fail_closed():
    p=providers(); old=p['netapp_ontap']()
    from dataclasses import replace
    p['netapp_ontap']=lambda:replace(old,observed_at='2026-10-14T20:00:00Z')
    c=client(provs=p)
    assert c.get('/api/v1/operations/nas-provenance/netapp_ontap/pure_flashblade').status_code==503
    assert 'UNAVAILABLE' in c.get('/operations/nas-provenance').text
def test_html_escape():
    c=client()
    assert 'Content-Security-Policy' in c.get('/operations/nas-provenance').headers
    assert '<script>' not in c.get('/operations/nas-provenance').text
def test_no_secret_leak():
    p=providers(); p['netapp_ontap']=lambda:(_ for _ in ()).throw(RuntimeError('SECRET_TOKEN'))
    c=client(provs=p)
    assert 'SECRET_TOKEN' not in c.get('/operations/nas-provenance').text
    assert 'SECRET_TOKEN' not in c.get('/api/v1/operations/nas-provenance/netapp_ontap/pure_flashblade').text
def test_invalid_setup():
    with pytest.raises(ValueError): attach_provenance_dashboard(FastAPI(),authorize=lambda r:True,providers={})
