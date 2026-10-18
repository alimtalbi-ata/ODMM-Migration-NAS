import hashlib
import json
import pytest
from qualification_custody_state_v2230 import seal_state
from qualification_witness_rotation_v2232 import stage_rotation,commit_rotation,rotation_status
S=b'v'*32

def setup(tmp_path):
    old=tmp_path/'old.json'; new=tmp_path/'new.json'; rotation=tmp_path/'rotation.json'
    for path,count in ((old,1),(new,2)):
        path.write_text(json.dumps(seal_state({'status':'CUSTODY_CONFIRMED','head':{'verified':True,'checkpoint_count':count,'current_count':count}},S)))
    return old,new,rotation

def digest(path):
    return hashlib.sha256(json.dumps(json.loads(path.read_text()),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()

def test_prepare_commit(tmp_path):
    old,new,r=setup(tmp_path)
    stage_rotation(old,new,r,secret=S)
    assert rotation_status(r,secret=S)=='PREPARED'
    result=commit_rotation(old,new,r,secret=S,independent_ack_sha256=digest(new))
    assert result['cutover_authorized'] is False
    assert rotation_status(r,secret=S)=='COMMITTED'
    assert json.loads(old.read_text())==json.loads(new.read_text())

def test_no_ack_no_change(tmp_path):
    old,new,r=setup(tmp_path); before=old.read_text()
    stage_rotation(old,new,r,secret=S)
    with pytest.raises(ValueError,match='WITNESS_ACK_MISMATCH'):
        commit_rotation(old,new,r,secret=S,independent_ack_sha256='bad')
    assert old.read_text()==before

def test_tamper_rotation(tmp_path):
    old,new,r=setup(tmp_path); stage_rotation(old,new,r,secret=S)
    rec=json.loads(r.read_text());rec['payload']['phase']='COMMITTED';r.write_text(json.dumps(rec))
    with pytest.raises(ValueError,match='WITNESS_ROTATION_UNVERIFIED'):
        rotation_status(r,secret=S)

def test_duplicate_stage_refused(tmp_path):
    old,new,r=setup(tmp_path);stage_rotation(old,new,r,secret=S)
    with pytest.raises(ValueError,match='WITNESS_ROTATION_ALREADY_PENDING'):
        stage_rotation(old,new,r,secret=S)

def test_changed_old_refused(tmp_path):
    old,new,r=setup(tmp_path);stage_rotation(old,new,r,secret=S)
    old.write_text(new.read_text())
    with pytest.raises(ValueError,match='WITNESS_OLD_CHANGED'):
        commit_rotation(old,new,r,secret=S,independent_ack_sha256=digest(new))

def test_rollback_refused(tmp_path):
    old,new,r=setup(tmp_path)
    new.write_text(json.dumps(seal_state({'status':'CUSTODY_CONFIRMED','head':{'verified':True,'checkpoint_count':0,'current_count':0}},S)))
    with pytest.raises(ValueError,match='WITNESS_ROLLBACK'):
        stage_rotation(old,new,r,secret=S)
