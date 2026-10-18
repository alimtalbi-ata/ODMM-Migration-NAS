import pytest
from fastapi import FastAPI
from qualification_secure_integration_v2235 import (
    attach_production_review_portal, recover_production_anchor, rotate_production_witness)
from test_qualification_witness_rotation_v2232 import setup, digest, S


def test_reject_missing_origins(tmp_path):
    with pytest.raises(ValueError, match='TRUSTED_ORIGINS'):
        attach_production_review_portal(FastAPI(), trusted_origins=[], anchor_path=tmp_path/'a')


def test_reject_insecure_origin(tmp_path):
    with pytest.raises(ValueError, match='ORIGIN_INVALID'):
        attach_production_review_portal(FastAPI(), trusted_origins=['http://localhost'], anchor_path=tmp_path/'a')


def test_reject_missing_anchor(tmp_path):
    with pytest.raises(ValueError, match='ANCHOR_REQUIRED'):
        attach_production_review_portal(FastAPI(), trusted_origins=['https://odmm.example'], anchor_path=tmp_path/'a')


def test_reject_production_recovery_downgrade():
    with pytest.raises(ValueError, match='CONFIGURATION_REQUIRED'):
        recover_production_anchor('db','anchor', custody_ack_path=None, custody_witness_path=None,
          custody_path=None,audit_path=None,external_receipt_path=None,
          custodian_key=None,custodian=None,operator=None)


def test_production_rotation_success(tmp_path):
    old,new,r=setup(tmp_path)
    ind=tmp_path/'independent.json'; ind.write_bytes(old.read_bytes())
    result=rotate_production_witness(old,new,r,secret=S,
        independent_current_witness=ind, independent_ack_sha256=digest(new))
    assert result['phase']=='COMMITTED' and result['cutover_authorized'] is False


def test_production_rotation_refuses_missing_ack(tmp_path):
    old,new,r=setup(tmp_path)
    with pytest.raises(ValueError,match='INDEPENDENT_ACK_REQUIRED'):
        rotate_production_witness(old,new,r,secret=S,independent_current_witness='x',independent_ack_sha256='')
