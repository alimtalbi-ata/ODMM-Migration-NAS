import json
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_transport_v2139 import make_vendor_reader,attach_nas_access_dashboard
from odmm_nas_probe_adapters_v2138 import collect_readonly_evidence

@pytest.mark.parametrize('vendor',('netapp_ontap','pure_flashblade','dell_onefs'))
def test_readonly_transport(vendor):
    calls=[]
    def get(url,**kwargs):
        calls.append((url,kwargs)); return b'{"items":[]}'
    result=make_vendor_reader(vendor=vendor,base_url='https://nas.example:443',transport=get)()
    assert result['vendor']==vendor and not result['certified'] and not result['cutover_authorized']
    assert calls[0][1]=={'max_bytes':1048576,'redirects':False,'tls_verify':True}

@pytest.mark.parametrize('url',('http://nas.example:443','https://localhost:443','https://user:pass@nas.example:443','https://nas.example','https://nas.example:443/path','https://nas.example:443?x=1'))
def test_bad_url(url):
    with pytest.raises(ValueError):make_vendor_reader(vendor='netapp_ontap',base_url=url,transport=lambda *a,**k:b'{}')

def test_redaction_and_failclosed():
    def transport(*a,**k):raise RuntimeError('TOP_SECRET')
    reader=make_vendor_reader(vendor='dell_onefs',base_url='https://nas.example:443',transport=transport)
    with pytest.raises(ValueError,match='VENDOR_READ_FAILED') as err:reader()
    assert 'TOP_SECRET' not in str(err.value)
    for payload in (b'{"token":"secret"}',b'[]',b'X'*1048577):
        reader=make_vendor_reader(vendor='dell_onefs',base_url='https://nas.example:443',transport=lambda *a,**k:payload)
        with pytest.raises(ValueError):reader()

def test_dashboard_auth_and_six_pairs():
    vendors=('netapp_ontap','pure_flashblade','dell_onefs')
    def make(v):
        return collect_readonly_evidence(vendor=v,firmware='test',collection_id='synthetic',requests=[{'principal':'EXAMPLE\\alice','path':'/data','right':'READ'}],collector=lambda *a:{'allowed':True,'method':'ACL_READONLY','identity_resolved':True})
    app=FastAPI(); attach_nas_access_dashboard(app,authorize=lambda r:r.headers.get('x-auth')=='yes',providers={v:lambda v=v:make(v) for v in vendors})
    c=TestClient(app)
    assert c.get('/operations/nas-access').status_code==403
    r=c.get('/operations/nas-access',headers={'x-auth':'yes'})
    assert r.status_code==200 and r.text.count('<tr>')==7 and 'BLOCKED' in r.text
    assert r.headers['cache-control']=='no-store' and c.post('/operations/nas-access').status_code==405
