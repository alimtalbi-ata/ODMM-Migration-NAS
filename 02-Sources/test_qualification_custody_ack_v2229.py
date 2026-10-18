import json
import pytest
from qualification_recovery_audit_v2225 import append_recovery_audit
from qualification_recovery_custody_v2226 import export_custody
from qualification_external_receipt_v2228 import issue_receipt
from qualification_custody_ack_v2229 import mark_pending, confirm_custody, read_ack_state
from qualification_review_coordination_v2220 import recover_anchor_supervised
from qualification_review_security_v2217 import review_head
KEY=b'k'*32
CK=b'z'*32

def setup(tmp_path):
    audit=tmp_path/'audit'; custody=tmp_path/'custody'; receipt=tmp_path/'receipt'; state=tmp_path/'state'
    record=export_custody(audit,custody,KEY)
    receipt.write_text(json.dumps(issue_receipt(record,custodian='store',reference='one',custodian_key=CK)))
    return audit,custody,receipt,state

def test_confirm_pending_receipt(tmp_path):
    audit,custody,receipt,state=setup(tmp_path)
    mark_pending(state,audit,custody,KEY)
    assert confirm_custody(state,audit,custody,receipt,secret=KEY,custodian_key=CK,custodian='store')['status']=='CUSTODY_CONFIRMED'

def test_missing_receipt_stays_pending(tmp_path):
    audit,custody,receipt,state=setup(tmp_path);mark_pending(state,audit,custody,KEY);receipt.unlink()
    with pytest.raises(ValueError): confirm_custody(state,audit,custody,receipt,secret=KEY,custodian_key=CK,custodian='store')
    assert read_ack_state(state,secret=KEY)['status']=='PENDING_CUSTODY_ACK'

def test_changed_head_refused(tmp_path):
    audit,custody,receipt,state=setup(tmp_path);mark_pending(state,audit,custody,KEY)
    append_recovery_audit(audit,KEY,operator='op',confirmed_head={'schema':'v','count':0,'head_mac':'GENESIS'})
    export_custody(audit,custody,KEY)
    with pytest.raises(ValueError,match='CUSTODY_HEAD_CHANGED'):
        confirm_custody(state,audit,custody,receipt,secret=KEY,custodian_key=CK,custodian='store')

def test_pending_blocks_recovery(tmp_path):
    audit,custody,receipt,state=setup(tmp_path);mark_pending(state,audit,custody,KEY)
    db=tmp_path/'db';anchor=tmp_path/'anchor';head=review_head(db,KEY)
    with pytest.raises(ValueError,match='PENDING_CUSTODY_ACK'):
        recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac=head['head_mac'],expected_count=head['count'],audit_path=audit,operator='op',custody_path=custody,custody_ack_path=state)
    assert not anchor.exists()

def test_missing_state_blocks_recovery(tmp_path):
    audit,custody,receipt,state=setup(tmp_path)
    db=tmp_path/'db';anchor=tmp_path/'anchor';head=review_head(db,KEY)
    with pytest.raises(ValueError,match='CUSTODY_ACK_STATE_UNVERIFIED'):
        recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac=head['head_mac'],expected_count=head['count'],audit_path=audit,operator='op',custody_path=custody,custody_ack_path=state)
