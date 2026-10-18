from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from odmm_nas_access_detail_v2142 import attach_nas_access_detail
from odmm_nas_probe_adapters_v2138 import collect_readonly_evidence

V=('netapp_ontap','pure_flashblade','dell_onefs')
def evidence(v, allowed=True):
    return collect_readonly_evidence(vendor=v,firmware='test',collection_id='synthetic',requests=[{'principal':'<admin>&','path':'/data','right':'READ'}],collector=lambda *a:{'allowed':allowed,'method':'ACL_READONLY','identity_resolved':True})
def client(allow=True, different=False):
    app=FastAPI(); providers={v:lambda v=v:evidence(v,not different or v!='pure_flashblade') for v in V}
    attach_nas_access_detail(app,authorize=lambda r:allow,providers=providers)
    return TestClient(app)
def test_authorization():
    assert client(False).get('/operations/nas-access/detail/netapp_ontap/pure_flashblade').status_code==403
@pytest.mark.parametrize('a,b',[(a,b) for a in V for b in V if a!=b])
def test_six_directions(a,b):
    r=client().get(f'/operations/nas-access/detail/{a}/{b}')
    assert r.status_code==200 and 'BLOCKED' in r.text and 'sha256' not in r.text
    assert r.headers['cache-control']=='no-store' and "default-src 'none'" in r.headers['content-security-policy']
def test_invalid_pair():
    assert client().get('/operations/nas-access/detail/netapp_ontap/netapp_ontap').status_code==400
def test_discrepancy_escaped():
    r=client(different=True).get('/operations/nas-access/detail/netapp_ontap/pure_flashblade')
    assert r.status_code==200 and '&lt;admin&gt;&amp;' in r.text and '<admin>' not in r.text
def test_provider_failure():
    app=FastAPI(); providers={v:lambda: (_ for _ in ()).throw(RuntimeError('SECRET')) for v in V}
    attach_nas_access_detail(app,authorize=lambda r:True,providers=providers)
    r=TestClient(app).get('/operations/nas-access/detail/netapp_ontap/pure_flashblade')
    assert r.status_code==503 and 'SECRET' not in r.text
def test_provider_required():
    with pytest.raises(ValueError):attach_nas_access_detail(FastAPI(),authorize=lambda r:True,providers={})
