import pytest
from qualification_jwks_custody_v2241 import JWKSWitnessHandoff, receipt_for
from qualification_oidc_custody_gate_v2242 import CustodyGatedJWKSRotation
from qualification_jwks_persistent_v2239 import PersistentJWKSRotation
from test_qualification_jwks_persistent_v2239 import key

S=b's'*32
C=b'c'*32

def fixture(tmp_path):
    jwks={'keys':[key('a')]}
    cfg=dict(path=tmp_path/'jwks.db',issuer='https://id.example',audience='odmm',initial_jwks=jwks)
    state=PersistentJWKSRotation(**cfg).state
    handoff=JWKSWitnessHandoff(ledger_path=tmp_path/'custody.db', witness_path=tmp_path/'witness.json', witness_secret=S, custody_secret=C)
    gate=dict(**cfg,witness_path=tmp_path/'witness.json',witness_secret=S,custody_ledger_path=tmp_path/'custody.db',custody_secret=C)
    return state,handoff,gate

def test_pending_blocks_start(tmp_path):
    state,h,gate=fixture(tmp_path)
    w=h.prepare(state)
    with pytest.raises(ValueError): CustodyGatedJWKSRotation(**gate)
    h.confirm(receipt=receipt_for(w,custodian='vault',reference='a',custody_secret=C),current_state=state)
    assert CustodyGatedJWKSRotation(**gate).assert_custody()

def test_missing_ledger_blocks(tmp_path):
    state,h,gate=fixture(tmp_path)
    with pytest.raises(ValueError): CustodyGatedJWKSRotation(**gate)

def test_tamper_after_start_blocks(tmp_path):
    state,h,gate=fixture(tmp_path);w=h.prepare(state)
    h.confirm(receipt=receipt_for(w,custodian='vault',reference='a',custody_secret=C),current_state=state)
    g=CustodyGatedJWKSRotation(**gate)
    import sqlite3
    with sqlite3.connect(gate['custody_ledger_path']) as db:
        db.execute("UPDATE handoff SET receipt='{}' WHERE id=1")
    with pytest.raises(ValueError):g.assert_custody()

def test_stale_generation_blocks(tmp_path):
    state,h,gate=fixture(tmp_path);w=h.prepare(state)
    h.confirm(receipt=receipt_for(w,custodian='vault',reference='a',custody_secret=C),current_state=state)
    g=CustodyGatedJWKSRotation(**gate)
    from qualification_jwks_rotation_v2238 import jwks_digest
    new={'keys':[gate['initial_jwks']['keys'][0],key('b')]}
    g.rotation.rotate(jwks=new,expected_generation=0,expected_sha256=jwks_digest(new),expected_previous_sha256=jwks_digest(gate['initial_jwks']))
    with pytest.raises(ValueError):g.assert_custody()
