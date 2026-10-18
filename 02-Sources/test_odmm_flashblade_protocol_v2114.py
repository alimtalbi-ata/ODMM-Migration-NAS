import pytest
from odmm_flashblade_protocol_v2114 import compare_protocol_configuration,build_readonly_report,FIELDS

@pytest.mark.parametrize('direction',['NETAPP_TO_FLASHBLADE','FLASHBLADE_TO_NETAPP'])
@pytest.mark.parametrize('protocol',['NFS','SMB'])
def test_identical_still_blocked(direction,protocol):
    evidence={key: False for key in FIELDS[protocol]}
    result=compare_protocol_configuration(evidence,evidence,protocol=protocol,direction=direction)
    assert all(c['status']=='MATCH' for c in result['checks'])
    assert result['cutover_authorized'] is False

@pytest.mark.parametrize('direction',['NETAPP_TO_FLASHBLADE','FLASHBLADE_TO_NETAPP'])
@pytest.mark.parametrize('protocol',['NFS','SMB'])
def test_mismatch(direction,protocol):
    key=FIELDS[protocol][0]
    result=compare_protocol_configuration({key:'a'},{key:'b'},protocol=protocol,direction=direction)
    assert 'MISMATCH_'+key.upper() in result['blockers']
    assert result['cutover_authorized'] is False

def test_missing_evidence():
    r=compare_protocol_configuration({}, {},protocol='NFS',direction='NETAPP_TO_FLASHBLADE')
    assert all(x['status']=='UNVERIFIED' for x in r['checks'])

def test_invalid_protocol():
    with pytest.raises(ValueError): compare_protocol_configuration({}, {},protocol='S3',direction='NETAPP_TO_FLASHBLADE')

def test_invalid_direction():
    with pytest.raises(ValueError): compare_protocol_configuration({}, {},protocol='NFS',direction='X')

def test_report_both():
    r=build_readonly_report({}, {},direction='FLASHBLADE_TO_NETAPP')
    assert r['nfs']['status']==r['smb']['status']=='BLOCKED'
