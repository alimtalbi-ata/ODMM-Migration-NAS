import json
import pytest
from fastapi import HTTPException
from qualification_custody_state_v2230 import seal_state
from qualification_custody_ack_v2229 import read_ack_state, confirm_custody
from qualification_review_coordination_v2220 import recover_anchor_supervised

SECRET=b's'*32
HEAD={'verified':True,'checkpoint_count':0,'current_count':0}

def test_secure_recovery_requires_independent_witness(tmp_path):
    with pytest.raises(ValueError,match='SECURE_CUSTODY_CONFIGURATION_REQUIRED'):
        recover_anchor_supervised(tmp_path/'db',tmp_path/'anchor',secret=SECRET,
            expected_head_mac='x',expected_count=0,secure_custody=True)

def test_secure_recovery_rejects_stale_witness_before_db_read(tmp_path):
    state=tmp_path/'state'; witness=tmp_path/'witness'
    state.write_text(json.dumps(seal_state({'status':'CUSTODY_CONFIRMED','head':HEAD},SECRET)))
    witness.write_text(json.dumps(seal_state({'status':'PENDING_CUSTODY_ACK','head':HEAD},SECRET)))
    with pytest.raises(ValueError,match='CUSTODY_ACK_STATE_UNVERIFIED'):
        recover_anchor_supervised(tmp_path/'db',tmp_path/'anchor',secret=SECRET,
            expected_head_mac='x',expected_count=0,secure_custody=True,
            custody_ack_path=state,custody_witness_path=witness,
            custody_path=tmp_path/'custody',audit_path=tmp_path/'audit')

def test_secure_confirmation_requires_witness(tmp_path):
    with pytest.raises(ValueError,match='SECURE_CUSTODY_WITNESS_REQUIRED'):
        confirm_custody(tmp_path/'state',tmp_path/'audit',tmp_path/'custody',tmp_path/'receipt',
            secret=SECRET,custodian_key=SECRET,custodian='vault',secure_custody=True)

def test_missing_witness_fails_closed(tmp_path):
    state=tmp_path/'state';state.write_text(json.dumps(seal_state({'status':'CUSTODY_CONFIRMED','head':HEAD},SECRET)))
    with pytest.raises(ValueError,match='CUSTODY_ACK_STATE_UNVERIFIED'):
        read_ack_state(state,secret=SECRET,witness_path=tmp_path/'missing')

def test_exact_witness_succeeds(tmp_path):
    record=seal_state({'status':'CUSTODY_CONFIRMED','head':HEAD},SECRET)
    state=tmp_path/'state'; witness=tmp_path/'witness'
    state.write_text(json.dumps(record));witness.write_text(json.dumps(record))
    assert read_ack_state(state,secret=SECRET,witness_path=witness)['status']=='CUSTODY_CONFIRMED'
