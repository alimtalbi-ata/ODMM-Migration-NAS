import json
import pytest
from qualification_witness_rotation_v2232 import (rotation_lock, stage_rotation_guarded,
    commit_rotation_guarded, reconcile_committing, _atomic, _signed)
from test_qualification_witness_rotation_v2232 import setup, digest, S

def test_guarded_rotation(tmp_path):
    old,new,r=setup(tmp_path)
    stage_rotation_guarded(old,new,r,secret=S)
    assert commit_rotation_guarded(old,new,r,secret=S,independent_ack_sha256=digest(new))['phase']=='COMMITTED'

def test_lock_contention(tmp_path):
    old,new,r=setup(tmp_path)
    with rotation_lock(r):
        with pytest.raises(ValueError,match='LOCKED'):
            stage_rotation_guarded(old,new,r,secret=S)

def test_stale_lock_not_stolen(tmp_path):
    old,new,r=setup(tmp_path)
    (tmp_path/'rotation.json.lock').write_text('dead process')
    with pytest.raises(ValueError,match='LOCKED'):
        stage_rotation_guarded(old,new,r,secret=S)

def test_reconcile_after_witness_replacement(tmp_path):
    old,new,r=setup(tmp_path)
    stage_rotation_guarded(old,new,r,secret=S)
    payload=json.loads(r.read_text())['payload']
    _atomic(r,_signed({**payload,'phase':'COMMITTING'},S))
    with pytest.raises(ValueError,match='REQUIRES_OPERATOR'):
        reconcile_committing(old,new,r,secret=S,independent_ack_sha256=digest(new))
    old.write_text(new.read_text())
    with pytest.raises(ValueError,match='ACK_MISMATCH'):
        reconcile_committing(old,new,r,secret=S,independent_ack_sha256='bad')
    assert reconcile_committing(old,new,r,secret=S,independent_ack_sha256=digest(new))['phase']=='COMMITTED'
