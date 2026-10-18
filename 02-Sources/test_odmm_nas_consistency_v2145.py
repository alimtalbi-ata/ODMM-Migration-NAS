import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_consistency_v2145 import crosscheck
from odmm_nas_audit_export_v2145 import attach_nas_consistency_export
from odmm_operations_portal import PAGE

VENDORS=('netapp_ontap','pure_flashblade','dell_onefs')
def sample():
    return {'namespaces':[{'path':'/share','protocol':'SMB3'}],'identities':[{'principal':'alice','resolved':True}],'accesses':[{'path':'/share','protocol':'SMB3','principal':'alice','right':'READ','allowed':True}]}
@pytest.mark.parametrize('vendor',VENDORS)
def test_valid(vendor):
    result=crosscheck(vendor=vendor,**sample())
    assert result['issues']==[] and result['status']=='BLOCKED' and result['cutover_authorized'] is False

def test_missing_namespace():
    data=sample();data['accesses'][0]['path']='/missing'
    assert crosscheck(vendor=VENDORS[0],**data)['issues']==['ACCESS_NAMESPACE_NOT_IN_INVENTORY']
def test_unresolved_identity():
    data=sample();data['identities'][0]['resolved']=False
    assert crosscheck(vendor=VENDORS[0],**data)['issues']==['ACCESS_IDENTITY_UNRESOLVED']
def test_duplicate_access():
    data=sample();data['accesses'].append(dict(data['accesses'][0]))
    with pytest.raises(ValueError,match='DUPLICATE_ACCESS'): crosscheck(vendor=VENDORS[0],**data)
def test_strict_bool():
    data=sample();data['accesses'][0]['allowed']=1
    with pytest.raises(ValueError,match='INVALID_ACCESS_ROW'): crosscheck(vendor=VENDORS[0],**data)
def test_auth_export():
    app=FastAPI(); attach_nas_consistency_export(app,authorize=lambda r:r.headers.get('x-test')=='ok',providers={v:sample for v in VENDORS})
    client=TestClient(app)
    assert client.get('/api/v1/operations/nas-consistency/export').status_code==403
    r=client.get('/api/v1/operations/nas-consistency/export',headers={'x-test':'ok'})
    assert r.status_code==200 and r.json()['cutover_authorized'] is False and len(r.json()['reports'])==3
    assert r.headers['cache-control']=='no-store' and 'attachment' in r.headers['content-disposition']
    assert client.post('/api/v1/operations/nas-consistency/export').status_code==405

def test_provider_failure_masked():
    app=FastAPI(); providers={v:sample for v in VENDORS};providers['dell_onefs']=lambda:1/0
    attach_nas_consistency_export(app,authorize=lambda r:True,providers=providers)
    r=TestClient(app).get('/api/v1/operations/nas-consistency/export')
    assert r.status_code==503 and 'ZeroDivision' not in r.text

def test_operations_navigation():
    for route in ('/operations/nas-pairs','/operations/nas-access','/operations/nas-provenance','/api/v1/operations/nas-consistency/export'):
        assert route in PAGE
