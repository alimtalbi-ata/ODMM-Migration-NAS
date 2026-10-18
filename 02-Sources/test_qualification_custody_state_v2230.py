import json
import pytest
from qualification_custody_state_v2230 import seal_state, verify_state, verify_witness
from qualification_custody_ack_v2229 import read_ack_state

SECRET = b'k' * 32
STATE = {'status':'PENDING_CUSTODY_ACK', 'head':{'verified':True,'checkpoint_count':0,'current_count':0}}

def test_valid_signed_state(tmp_path):
    p=tmp_path/'ack'; p.write_text(json.dumps(seal_state(STATE, SECRET)))
    assert read_ack_state(p,secret=SECRET)==STATE

def test_tamper_detected(tmp_path):
    p=tmp_path/'ack'; data=seal_state(STATE,SECRET); data['payload']['status']='CUSTODY_CONFIRMED';p.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='UNVERIFIED'): read_ack_state(p,secret=SECRET)

def test_unsigned_refused(tmp_path):
    p=tmp_path/'ack';p.write_text(json.dumps(STATE))
    with pytest.raises(ValueError,match='UNVERIFIED'):read_ack_state(p,secret=SECRET)

def test_wrong_key_refused():
    with pytest.raises(ValueError,match='UNVERIFIED'):verify_state(seal_state(STATE,SECRET),b'z'*32)

def test_independent_witness_detects_rollback(tmp_path):
    p=tmp_path/'witness'; confirmed={**STATE,'status':'CUSTODY_CONFIRMED'}
    p.write_text(json.dumps(seal_state(confirmed,SECRET)))
    with pytest.raises(ValueError,match='WITNESS_MISMATCH'):verify_witness(STATE,p,SECRET)
    assert verify_witness(confirmed,p,SECRET)

def test_missing_witness_fails(tmp_path):
    with pytest.raises(ValueError,match='WITNESS_MISMATCH'):verify_witness(STATE,tmp_path/'absent',SECRET)
