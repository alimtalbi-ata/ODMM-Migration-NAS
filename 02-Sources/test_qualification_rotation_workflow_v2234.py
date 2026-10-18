import json
import pytest
from qualification_rotation_workflow_v2234 import guarded_recovery_rotation
from qualification_witness_rotation_v2232 import rotation_lock, _atomic, _signed
from test_qualification_witness_rotation_v2232 import setup, digest, S


def invoke(old,new,r,ind):
    return guarded_recovery_rotation(old,new,r,secret=S,independent_current_witness=ind,
                                     independent_ack_sha256=digest(new))


def test_valid_secure_rotation(tmp_path):
    old,new,r=setup(tmp_path)
    ind=tmp_path/'independent.json'; ind.write_bytes(old.read_bytes())
    assert invoke(old,new,r,ind)['phase']=='COMMITTED'


def test_missing_independent_witness(tmp_path):
    old,new,r=setup(tmp_path)
    with pytest.raises(ValueError,match='SECURE_WITNESS_UNVERIFIED'):
        invoke(old,new,r,tmp_path/'missing')
    assert not r.exists()


def test_divergent_witness(tmp_path):
    old,new,r=setup(tmp_path)
    ind=tmp_path/'independent.json'; ind.write_bytes(new.read_bytes())
    with pytest.raises(ValueError,match='DIVERGED'):
        invoke(old,new,r,ind)


def test_interrupted_commit_blocked(tmp_path):
    old,new,r=setup(tmp_path)
    ind=tmp_path/'independent.json'; ind.write_bytes(old.read_bytes())
    _atomic(r,_signed({'phase':'COMMITTING','old_sha256':digest(old),'new_sha256':digest(new)},S))
    with pytest.raises(ValueError,match='SUPERVISED_RECONCILIATION'):
        invoke(old,new,r,ind)


def test_lock_contention(tmp_path):
    old,new,r=setup(tmp_path)
    ind=tmp_path/'independent.json'; ind.write_bytes(old.read_bytes())
    with rotation_lock(r):
        with pytest.raises(ValueError,match='LOCKED'):
            invoke(old,new,r,ind)
