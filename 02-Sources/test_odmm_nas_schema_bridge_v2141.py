import json
import pytest
from odmm_nas_qualified_reader_v2140 import Profile
from odmm_nas_schema_bridge_v2141 import SchemaContract, collect_and_validate, validate_inventory

VENDORS=('netapp_ontap','pure_flashblade','dell_onefs')
def get(vendor, rows=None):
    rows=[{'id':'one','name':'data'}] if rows is None else rows
    return collect_and_validate(base_url='https://nas.example.org:443',
        profile=Profile(vendor,'1.0','/api/inventory','records','next','EVID'),
        contract=SchemaContract(vendor,('id','name'),'id'),
        transport=lambda *a,**k:json.dumps({'records':rows,'next':None}).encode(),
        authorization='Bearer test')
@pytest.mark.parametrize('vendor',VENDORS)
def test_supported_vendor(vendor):
    x=get(vendor)
    assert x['record_count']==1 and not x['certified'] and not x['cutover_authorized']
@pytest.mark.parametrize('rows,code',[
    ([{'id':'a'}],'SCHEMA_MISMATCH'),
    ([{'id':'a','name':'x'},{'id':'a','name':'y'}],'DUPLICATE_IDENTIFIER'),
    ([{'id':42,'name':'x'}],'INVALID_IDENTIFIER'),
    ([{'id':'a\n','name':'x'}],'INVALID_IDENTIFIER'),
])
def test_invalid_rows(rows,code):
    with pytest.raises(ValueError,match=code):get('netapp_ontap',rows)
def test_profile_mismatch():
    with pytest.raises(ValueError,match='PROFILE_CONTRACT_MISMATCH'):
        collect_and_validate(base_url='https://nas.example.org:443',
          profile=Profile('netapp_ontap','1.0','/api/inventory','records','next','EVID'),
          contract=SchemaContract('dell_onefs',('id',),'id'),transport=lambda *a,**k:b'{}',authorization='Bearer test')
def test_reject_forged_certification():
    with pytest.raises(ValueError,match='UNTRUSTED_COLLECTION'):
        validate_inventory(collected={'vendor':'netapp_ontap','pagination_complete':True,'certified':True,'cutover_authorized':False,'records':[],'record_count':0},contract=SchemaContract('netapp_ontap',('id',),'id'))
def test_empty_inventory_not_certified():
    assert get('dell_onefs',[])['record_count']==0
