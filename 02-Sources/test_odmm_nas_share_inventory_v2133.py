import pytest
from odmm_nas_share_inventory_v2133 import normalize_namespaces, compare_namespaces
V=['netapp_ontap','pure_flashblade','dell_onefs']
def build(v,records=(),**kw):
    p=dict(vendor=v,firmware='fw',endpoint_id='e',records=list(records),pagination_complete=True,
           provenance=dict(vendor=v,firmware='fw',endpoint_id='e',evidence_id='ev',collector_id='collector'))
    p.update(kw)
    return normalize_namespaces(**p)
def row(v,kind='NFS',name='/data',path='/data'):
    return dict(vendor=v,endpoint_id='e',kind=kind,name=name,path=path)
@pytest.mark.parametrize('vendor',V)
def test_each_vendor(vendor):
    r=build(vendor,[row(vendor)]); assert len(r.exports)==1 and not r.cutover_authorized and not r.certified
@pytest.mark.parametrize('source',V)
@pytest.mark.parametrize('target',V)
def test_directions(source,target):
    if source==target: return
    a=build(source,[row(source)]); b=build(target)
    c=compare_namespaces(a,b); assert c['status']=='BLOCKED' and c['missing_nfs']
def test_smb_casefold_duplicate():
    v=V[0]
    with pytest.raises(ValueError,match='DUPLICATE'): build(v,[row(v,'SMB','Data'),row(v,'SMB','data')])
def test_wrong_endpoint():
    with pytest.raises(ValueError,match='ENDPOINT'): build(V[0],[row(V[1])])
def test_pagination():
    with pytest.raises(ValueError,match='PAGINATION'): build(V[0],pagination_complete=False)
def test_provenance():
    with pytest.raises(ValueError,match='PROVENANCE'): build(V[0],provenance={})
def test_traversal():
    with pytest.raises(ValueError,match='NAMESPACE'): build(V[0],[row(V[0],path='/a/../b',name='/a/../b')])
def test_no_self_certification():
    x=row(V[0]);x['acl_verified']=True
    with pytest.raises(ValueError,match='UNTRUSTED'):build(V[0],[x])
def test_deterministic_digest():
    v=V[0]; a=row(v);b=row(v,'SMB','DATA','/data')
    assert build(v,[a,b]).digest==build(v,[b,a]).digest
def test_smb_missing():
    a=build(V[0],[row(V[0],'SMB','Share','/a')]);b=build(V[1])
    assert compare_namespaces(a,b)['missing_smb']==(('Share','/a'),)
