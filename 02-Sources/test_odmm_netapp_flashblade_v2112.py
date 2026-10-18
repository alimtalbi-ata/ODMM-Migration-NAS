import pytest
from odmm_netapp_flashblade_v2112 import assess_pair

def endpoint(vendor):
    return dict(vendor=vendor,protocol='NFS4',namespace='/data',capacity_free_bytes=200,
                required_bytes=100,identity_domain='corp',acl_model='NFS4',features=['nfs4_acl'])

@pytest.mark.parametrize('source,target', [('netapp','flashblade'),('flashblade','netapp')])
def test_both_directions_block_cutover(source,target):
    result=assess_pair(endpoint(source),endpoint(target))
    assert result.direction==source+'_TO_'+target
    assert result.status=='BLOCKED' and not result.cutover_authorized
    assert result.engine=='ODMM_NATIVE'
    assert 'PROOF_REQUIRED_EFFECTIVE_ACCESS_VERIFIED' in result.blockers

def test_unknown_direction_blocked():
    assert 'UNSUPPORTED_VENDOR_DIRECTION' in assess_pair(endpoint('netapp'),endpoint('netapp')).blockers

def test_acl_drift_blocks():
    target=endpoint('flashblade'); target['acl_model']='POSIX'
    assert 'ACL_TRANSLATION_UNQUALIFIED' in assess_pair(endpoint('netapp'),target).blockers

def test_protocol_drift_blocks():
    target=endpoint('flashblade'); target['protocol']='SMB3'
    assert 'CROSS_PROTOCOL_TRANSLATION_UNQUALIFIED' in assess_pair(endpoint('netapp'),target).blockers

def test_insufficient_capacity_blocks():
    target=endpoint('flashblade'); target['capacity_free_bytes']=10
    assert 'TARGET_CAPACITY_INSUFFICIENT' in assess_pair(endpoint('netapp'),target).blockers

def test_unsupported_features_block():
    source=endpoint('netapp'); source['features']=['nfs4_acl','qtrees']
    assert 'FEATURE_TRANSLATION_REQUIRED_QTREES' in assess_pair(source,endpoint('flashblade')).blockers

def test_missing_identity_blocks():
    target=endpoint('flashblade'); target['identity_domain']=''
    assert 'TARGET_IDENTITY_UNVERIFIED' in assess_pair(endpoint('netapp'),target).blockers

def test_all_supplied_proofs_still_no_automatic_cutover():
    keys=('source_inventory','target_inventory','acl_sample_verified','effective_access_verified','identity_mapping_verified','delta_sync_verified','rollback_tested','fencing_verified','checksum_verified','protocol_semantics_verified')
    result=assess_pair(endpoint('netapp'),endpoint('flashblade'),dict.fromkeys(keys,True))
    assert result.blockers==() and not result.cutover_authorized

def test_missing_capacity_blocks():
    target=endpoint('flashblade'); del target['capacity_free_bytes']
    assert 'CAPACITY_EVIDENCE_UNVERIFIED' in assess_pair(endpoint('netapp'),target).blockers
