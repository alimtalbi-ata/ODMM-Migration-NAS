from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from odmm_nas_acl_portal_v2147 import attach_acl_audit_portal
from odmm_nas_acl_semantics_v2146 import normalize_acl,VENDORS

def evidence(v, protocol):
    return normalize_acl(vendor=v,protocol=protocol,share='/private/customer',domain='AD',identity_map={'secret-user':'canonical-1'},aces=[{'ordinal':0,'principal':'secret-user','effect':'ALLOW','rights':['READ'],'inherited':False,'inheritance_flags':[]}],complete=True)

def client(authorized=True, broken=None):
    app=FastAPI()
    providers={v:(lambda p,v=v: evidence(v,p)) for v in VENDORS}
    if broken: providers[broken]=lambda p: (_ for _ in ()).throw(RuntimeError('SECRET_ACCESS_TOKEN'))
    attach_acl_audit_portal(app,authorize=lambda r:authorized,providers=providers)
    return TestClient(app)

def test_all_six_directions():
    r=client().get('/api/v1/operations/nas-acl-audit')
    assert r.status_code==200 and len(r.json()['reports'])==6
    assert all(x['status']=='BLOCKED' and x['cutover_authorized'] is False for x in r.json()['reports'])
    assert 'secret-user' not in r.text and '/private/customer' not in r.text

def test_html_and_filter():
    r=client().get('/operations/nas-acl-audit?protocol=SMB3&source=netapp_ontap')
    assert r.status_code==200 and r.text.count('<tr>')==3
    assert 'secret-user' not in r.text and '/private/customer' not in r.text

def test_unauthorized():
    for path in ('/operations/nas-acl-audit','/api/v1/operations/nas-acl-audit'):
        assert client(False).get(path).status_code==403

def test_invalid_filters():
    for query in ('protocol=SMB2','source=evil','only=unsafe'):
        assert client().get('/api/v1/operations/nas-acl-audit?'+query).status_code==400

def test_errors_are_redacted():
    r=client(broken='dell_onefs').get('/api/v1/operations/nas-acl-audit')
    assert r.status_code==200 and r.json()['unavailable']==4
    assert 'SECRET_ACCESS_TOKEN' not in r.text

def test_bad_providers():
    with pytest.raises(ValueError): attach_acl_audit_portal(FastAPI(),authorize=lambda r:True,providers={})
