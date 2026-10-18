import json
import pytest
from odmm_nas_rest_adapter_v2132 import RestProfile, make_rest_page_fetcher, collect_rest_inventory

VENDORS=['netapp_ontap','pure_flashblade','dell_onefs']
def setup(v='netapp_ontap', **kw):
    p=RestProfile(v,'v1','/api/inventory','items','next','lab-fw',True)
    m=dict(vendor=v,model='lab',firmware='lab-fw',serial_ref='lab',protocols=['NFS4'],acl_models=['NFS4'],evidence_id='lab',collected_at='2026-10-15T12:00:00+00:00',collection_method='API_READONLY',read_only=True)
    d=dict(base_url='https://nas.example.org:443',profile=p,manifest=m,token='secret',transport=lambda *a:json.dumps({'items':[{'id':1}],'next':None}).encode())
    d.update(kw); return d
@pytest.mark.parametrize('vendor',VENDORS)
def test_all_vendors(vendor):
    r=collect_rest_inventory(**setup(vendor)); assert r.page_count==1 and not r.certified and not r.cutover_authorized

def test_pagination_and_url_encoding():
    urls=[]
    def t(url,*args):
        urls.append(url)
        return json.dumps({'items':[], 'next':'a&b' if len(urls)==1 else None}).encode()
    r=collect_rest_inventory(**setup(transport=t)); assert r.page_count==2 and urls[1].endswith('?cursor=a%26b')
@pytest.mark.parametrize('base',['http://nas.example.org:443','https://localhost:443','https://127.0.0.1:443','https://nas.example.org','https://x:y@nas.example.org:443','https://nas.example.org:443/evil','https://nas.example.org:443/?x=1'])
def test_reject_bad_base(base):
    with pytest.raises(ValueError): make_rest_page_fetcher(**setup(base_url=base))
def test_reject_unqualified():
    d=setup(); d['profile']=RestProfile('netapp_ontap','v1','/api/inventory','items','next','lab-fw',False)
    with pytest.raises(ValueError,match='UNQUALIFIED'): make_rest_page_fetcher(**d)
def test_reject_firmware_mismatch():
    d=setup(); d['manifest']['firmware']='other'
    with pytest.raises(ValueError,match='FIRMWARE'): make_rest_page_fetcher(**d)
@pytest.mark.parametrize('route',['/api/../secret','//other','/api?a=1'])
def test_reject_route(route):
    d=setup(); d['profile']=RestProfile('netapp_ontap','v1',route,'items','next','lab-fw',True)
    with pytest.raises(ValueError): make_rest_page_fetcher(**d)
def test_missing_next_key():
    f=make_rest_page_fetcher(**setup(transport=lambda *a:b'{"items":[]}'))
    with pytest.raises(ValueError,match='PAGINATION_COMPLETENESS'): f(None)
def test_invalid_json():
    f=make_rest_page_fetcher(**setup(transport=lambda *a:b'not json'))
    with pytest.raises(ValueError,match='JSON'): f(None)
def test_size_limit():
    f=make_rest_page_fetcher(**setup(transport=lambda *a:b'x'*2_000_001))
    with pytest.raises(ValueError,match='SIZE'): f(None)
def test_transport_failure_redacted():
    def fail(*a): raise RuntimeError('secret')
    f=make_rest_page_fetcher(**setup(transport=fail))
    with pytest.raises(ValueError,match='REST_TRANSPORT_FAILED'): f(None)
def test_no_implicit_promotion():
    d=setup(); d['manifest']['independently_certified']=True
    r=collect_rest_inventory(**d)
    assert not r.certified and 'NOT_INDEPENDENTLY_CERTIFIED' in r.blockers
