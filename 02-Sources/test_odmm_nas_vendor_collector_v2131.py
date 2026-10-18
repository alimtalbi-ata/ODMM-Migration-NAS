import pytest
from odmm_nas_vendor_collector_v2131 import collect_vendor_inventory

def manifest(v='netapp_ontap'):
    return dict(vendor=v,model='lab',firmware='unverified',serial_ref='sim',protocols=['NFS4'],acl_models=['NFS4'],evidence_id='lab',collected_at='2026-10-15T12:00:00+00:00',collection_method='API_READONLY',read_only=True)

def run(m=None,f=None,**kw):
    return collect_vendor_inventory(vendor='netapp_ontap',manifest=m or manifest(),fetch_page=f or (lambda _: {'records':[{'id':1}],'next_token':None}),**kw)

def test_happy():
    r=run(); assert r.page_count==1 and len(r.records)==1 and not r.certified and not r.cutover_authorized

def test_pagination():
    r=run(f=lambda t: {'records':[{'x':t}],'next_token':'next' if t is None else None}); assert r.page_count==2
@pytest.mark.parametrize('v',['bad','dell_unity',None])
def test_vendor(v):
    with pytest.raises(ValueError): collect_vendor_inventory(vendor=v,manifest=manifest(),fetch_page=lambda _: {})
def test_manifest_mismatch():
    with pytest.raises(ValueError): run(m=manifest('pure_flashblade'))
def test_read_only():
    m=manifest(); m['read_only']=False
    with pytest.raises(ValueError): run(m=m)
def test_cycle():
    with pytest.raises(ValueError): run(f=lambda _: {'records':[],'next_token':'x'})
def test_limit():
    with pytest.raises(ValueError): run(f=lambda _: {'records':[],'next_token':'x'},max_pages=1)
def test_bad_page():
    with pytest.raises(ValueError): run(f=lambda _: {'records':{}})
def test_bad_record():
    with pytest.raises(ValueError): run(f=lambda _: {'records':[3]})
def test_fetch_error():
    def fail(_): raise RuntimeError('network')
    with pytest.raises(ValueError,match='COLLECTION_PAGE_FAILED'): run(f=fail)
def test_no_false_certification():
    m=manifest(); m.update(inventory_complete=True,acl_evidence_complete=True,vendor_api_qualified=True)
    r=run(m=m); assert not r.certified and 'NOT_INDEPENDENTLY_CERTIFIED' in r.blockers
@pytest.mark.parametrize('v',['pure_flashblade','dell_onefs'])
def test_other_vendors(v):
    r=collect_vendor_inventory(vendor=v,manifest=manifest(v),fetch_page=lambda _: {'records':[],'next_token':None}); assert r.endpoint.vendor==v
