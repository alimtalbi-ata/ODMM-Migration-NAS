import sqlite3
import pytest
from qualification_jwks_custody_v2241 import JWKSWitnessHandoff, receipt_for
from qualification_jwks_recovery_v2244 import inspect_handoff
from qualification_jwks_witness_v2240 import create_witness_file

S=b's'*32; C=b'c'*32
STATE={'generation':2,'jwks_sha256':'a'*64}

def setup(tmp_path):
    h=JWKSWitnessHandoff(ledger_path=tmp_path/'ledger.db',witness_path=tmp_path/'witness.json',witness_secret=S,custody_secret=C)
    kw=dict(ledger_path=tmp_path/'ledger.db',witness_path=tmp_path/'witness.json',current_state=STATE,witness_secret=S,custody_secret=C)
    return h,kw

def test_pending_requires_replay(tmp_path):
    h,kw=setup(tmp_path); h.prepare(STATE)
    d=inspect_handoff(**kw)
    assert d['requires_operator_replay'] and not d['authentication_allowed'] and not d['witness_published']

def test_interrupted_after_publish_remains_blocked(tmp_path):
    h,kw=setup(tmp_path); h.prepare(STATE)
    create_witness_file(STATE,witness_path=kw['witness_path'],secret=S)
    d=inspect_handoff(**kw)
    assert d['witness_published'] and not d['authentication_allowed']

def test_confirmed_can_be_verified_after_restart(tmp_path):
    h,kw=setup(tmp_path); w=h.prepare(STATE)
    h.confirm(receipt=receipt_for(w,custodian='vault',reference='ref',custody_secret=C),current_state=STATE)
    assert inspect_handoff(**kw)['authentication_allowed']
    assert inspect_handoff(**kw)['state']=='CUSTODY_CONFIRMED'

def test_stale_generation_rejected(tmp_path):
    h,kw=setup(tmp_path); h.prepare(STATE)
    with pytest.raises(ValueError,match='STALE'):
        inspect_handoff(**{**kw,'current_state':{**STATE,'generation':3}})

def test_tampered_confirmed_receipt_rejected(tmp_path):
    h,kw=setup(tmp_path); w=h.prepare(STATE)
    h.confirm(receipt=receipt_for(w,custodian='vault',reference='ref',custody_secret=C),current_state=STATE)
    with sqlite3.connect(kw['ledger_path']) as db:
        db.execute("UPDATE handoff SET receipt='{}' WHERE id=1")
    with pytest.raises(ValueError,match='CUSTODY_RECEIPT_INVALID'):
        inspect_handoff(**kw)

def test_missing_ledger_rejected(tmp_path):
    with pytest.raises(ValueError,match='UNAVAILABLE'):
        inspect_handoff(ledger_path=tmp_path/'missing.db',witness_path=tmp_path/'missing.json',current_state=STATE,witness_secret=S,custody_secret=C)
