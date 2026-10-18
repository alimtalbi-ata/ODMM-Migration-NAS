import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_pair_portal_v2134 import attach_nas_pair_portal, VENDORS
from odmm_nas_share_inventory_v2133 import normalize_namespaces

def inventory(v, records=()):
    return normalize_namespaces(vendor=v, firmware='test', endpoint_id='test-endpoint', records=list(records),pagination_complete=True,
      provenance=dict(vendor=v,firmware='test',endpoint_id='test-endpoint',evidence_id='fixture',collector_id='fixture'))

def client(auth=lambda _: True, overrides=None):
    providers={v:(lambda v=v: inventory(v)) for v in VENDORS}
    providers.update(overrides or {})
    app=FastAPI(); attach_nas_pair_portal(app,authorize=auth,providers=providers)
    return TestClient(app)

@pytest.mark.parametrize('source', VENDORS)
@pytest.mark.parametrize('target', VENDORS)
def test_pairs(source,target):
    r=client().get(f'/api/v1/operations/nas-pairs/{source}/{target}')
    if source==target: assert r.status_code==400
    else:
        assert r.status_code==200 and r.json()['status']=='BLOCKED' and r.json()['cutover_authorized'] is False
        assert r.headers['cache-control']=='no-store'

def test_auth_fail_closed():
    c=client(auth=lambda _: 1)
    assert c.get('/operations/nas-pairs').status_code==403
    assert c.get('/api/v1/operations/nas-pairs/netapp_ontap/dell_onefs').status_code==403

def test_auth_exception():
    def bad(_): raise RuntimeError('offline')
    assert client(auth=bad).get('/operations/nas-pairs').status_code==403

def test_provider_failure():
    def bad(): raise RuntimeError('offline')
    r=client(overrides={'netapp_ontap':bad}).get('/api/v1/operations/nas-pairs/netapp_ontap/dell_onefs')
    assert r.status_code==503 and r.json()['cutover_authorized'] is False

def test_vendor_mismatch():
    r=client(overrides={'netapp_ontap':lambda:inventory('dell_onefs')}).get('/api/v1/operations/nas-pairs/netapp_ontap/dell_onefs')
    assert r.status_code==503

def test_invalid_provider_configuration():
    with pytest.raises(ValueError): attach_nas_pair_portal(FastAPI(),authorize=lambda _:True,providers={})

def test_html_all_six_directions():
    r=client().get('/operations/nas-pairs')
    assert r.status_code==200 and r.text.count('<tr><td>')==6 and 'Abdelhalim Talbi' in r.text
    assert 'Content-Security-Policy' in r.headers

def test_unknown_vendor():
    assert client().get('/api/v1/operations/nas-pairs/unknown/dell_onefs').status_code==400

def test_no_client_submitted_inventory():
    r=client().get('/api/v1/operations/nas-pairs/netapp_ontap/dell_onefs?cutover_authorized=true')
    assert r.json()['cutover_authorized'] is False
