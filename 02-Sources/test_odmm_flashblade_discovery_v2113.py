import pytest
from odmm_flashblade_discovery_v2113 import discover_flashblade, compare_nas_namespaces

def fetch(path):
    if 'file-systems?' in path:return {'items':[{'name':'finance','id':'fs-1'}]}
    if 'file-system-exports?' in path:return {'items':[{'name':'finance-nfs'}]}
    if 'smb-shares?' in path:return {'items':[]}
    raise AssertionError(path)

def test_inventory():
    x=discover_flashblade(fetch,filesystem_name='finance')
    assert x.endpoint['discovered_protocols']==('NFS',)
    assert x.endpoint['acl_model']=='UNVERIFIED'
    assert x.blockers==()

@pytest.mark.parametrize('direction', ['NETAPP_TO_FLASHBLADE','FLASHBLADE_TO_NETAPP'])
def test_bidirectional_mapping_blocked(direction):
    x=discover_flashblade(fetch,filesystem_name='finance')
    y=compare_nas_namespaces({'namespace_id':'svm:vol'},x,direction=direction)
    assert y['cutover_authorized'] is False and y['engine']=='ODMM_NATIVE'
    assert (y['source_namespace'],y['target_namespace']) == (('svm:vol','finance') if direction.startswith('NETAPP') else ('finance','svm:vol'))

def test_fetch_failure_closed():
    x=discover_flashblade(lambda p: (_ for _ in ()).throw(OSError()),filesystem_name='finance')
    assert len(x.blockers)>=3

def test_bad_response_closed():
    x=discover_flashblade(lambda p: {'records':[]},filesystem_name='finance')
    assert x.blockers

@pytest.mark.parametrize('name',['','/bad','?bad','#bad'])
def test_invalid_name(name):
    with pytest.raises(ValueError): discover_flashblade(fetch,filesystem_name=name)

def test_version_rejected():
    with pytest.raises(ValueError): discover_flashblade(fetch,filesystem_name='finance',api_version='1.x')

def test_invalid_direction():
    with pytest.raises(ValueError): compare_nas_namespaces({},discover_flashblade(fetch,filesystem_name='finance'),direction='OTHER')

def test_missing_ontap_namespace():
    x=compare_nas_namespaces({},discover_flashblade(fetch,filesystem_name='finance'),direction='NETAPP_TO_FLASHBLADE')
    assert 'NETAPP_NAMESPACE_UNVERIFIED' in x['blockers']
