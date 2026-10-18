import pytest
from odmm_nas_probe_adapters_v2138 import collect_readonly_evidence,compare_collected_evidence,attach_nas_access_audit
from fastapi import FastAPI
from fastapi.testclient import TestClient

R=[{'principal':'EXAMPLE\\alice','path':'/data/report','right':'READ'}]
def make(vendor,allow=True):
    return collect_readonly_evidence(vendor=vendor,firmware='test-firmware',collection_id='synthetic',requests=R,
        collector=lambda *args:{'allowed':allow,'method':'ACL_READONLY','identity_resolved':True})

def test_six_directions():
    vendors=('netapp_ontap','pure_flashblade','dell_onefs')
    for a in vendors:
        for b in vendors:
            if a!=b:
                result=compare_collected_evidence(make(a),make(b))
                assert result['checked']==1 and not result['cutover_authorized']

def test_mismatch():
    result=compare_collected_evidence(make('netapp_ontap'),make('pure_flashblade',False))
    assert len(result['discrepancies'])==1 and 'EFFECTIVE_ACCESS_MISMATCH' in result['blockers']

@pytest.mark.parametrize('result',[
    {'allowed':True,'method':'WRITE_TEST','identity_resolved':True},
    {'allowed':True,'method':'ACL_READONLY','identity_resolved':False},
    {'allowed':'true','method':'ACL_READONLY','identity_resolved':True},
    {'allowed':True,'method':'ACL_READONLY'},
])
def test_reject_untrusted_response(result):
    with pytest.raises(ValueError):
        collect_readonly_evidence(vendor='netapp_ontap',firmware='f',collection_id='c',requests=R,collector=lambda *a:result)

def test_transport_failure_redacted():
    def fail(*a):raise RuntimeError('SECRET_PASSWORD')
    with pytest.raises(ValueError,match='COLLECTOR_FAILED') as e:
        collect_readonly_evidence(vendor='netapp_ontap',firmware='f',collection_id='c',requests=R,collector=fail)
    assert 'SECRET_PASSWORD' not in str(e.value)

def test_incomplete_coverage():
    from dataclasses import replace
    a=make('netapp_ontap'); b=make('pure_flashblade')
    with pytest.raises(ValueError,match='INVALID_EVIDENCE_ROWS'):
        compare_collected_evidence(a,replace(b,observations=()))

def test_api_auth_and_readonly():
    app=FastAPI(); providers={v:(lambda v=v:make(v)) for v in ('netapp_ontap','pure_flashblade','dell_onefs')}
    attach_nas_access_audit(app,authorize=lambda r:r.headers.get('x-test-auth')=='yes',providers=providers)
    c=TestClient(app)
    url='/api/v1/operations/nas-access/netapp_ontap/pure_flashblade'
    assert c.get(url).status_code==403
    assert c.get(url,headers={'x-test-auth':'yes'}).json()['status']=='BLOCKED'
    assert c.post(url,headers={'x-test-auth':'yes'}).status_code==405
    assert c.get(url,headers={'x-test-auth':'yes'}).headers['cache-control']=='no-store'

def test_tampered_digest_rejected():
    from dataclasses import replace
    with pytest.raises(ValueError,match='EVIDENCE_DIGEST_MISMATCH'):
        compare_collected_evidence(replace(make('netapp_ontap'),digest='0'*64),make('pure_flashblade'))
