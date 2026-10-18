"""V217.4 triad gate tests. Author: Abdelhalim Talbi."""
import pytest
from odmm_nas_six_direction_gate_v2174 import assess, six_direction_report, REQUIRED

@pytest.mark.parametrize('protocol', ['NFS3','NFS4','SMB2','SMB3'])
def test_all_six_directions_fail_closed(protocol):
    rows=six_direction_report(protocol=protocol)
    assert len(rows)==6 and len({r.direction for r in rows})==6
    assert all(r.blocked and not r.cutover_authorized and r.missing==REQUIRED for r in rows)

def test_fabricated_complete_evidence_cannot_certify():
    s={'vendor':'netapp','protocol':'SMB3','namespace':'/src','inventory_complete':True}
    t={'vendor':'isilon','protocol':'SMB3','namespace':'/dst','inventory_complete':True}
    result=assess(s,t,{k:True for k in REQUIRED})
    assert result.missing==() and result.unverified==()
    assert result.blocked and not result.cutover_authorized and result.certification=='NOT_CERTIFIED'

def test_truthy_string_not_proof():
    s={'vendor':'flashblade','protocol':'NFS4','namespace':'/src','inventory_complete':True}
    t={'vendor':'netapp','protocol':'NFS4','namespace':'/dst','inventory_complete':True}
    result=assess(s,t,{'source_acl':'true'})
    assert result.unverified==('source_acl',)

def test_outside_scope_rejected():
    with pytest.raises(ValueError,match='OUTSIDE_SIX_DIRECTION_SCOPE'):
        assess({'vendor':'netapp'}, {'vendor':'synology'}, {})
