import pytest
from qualification_jwks_custody_v2241 import JWKSWitnessHandoff, receipt_for
from qualification_jwks_witness_v2240 import verify_witness

S=b's'*32
C=b'c'*32
STATE={'generation':2,'jwks_sha256':'a'*64}

def handoff(tmp_path):
    return JWKSWitnessHandoff(ledger_path=tmp_path/'handoff.db', witness_path=tmp_path/'witness.json', witness_secret=S, custody_secret=C)

def test_handoff_requires_custodian(tmp_path):
    h=handoff(tmp_path)
    w=h.prepare(STATE)
    assert h.status()=='PENDING_CUSTODY_ACK'
    with pytest.raises(ValueError, match='CUSTODY_RECEIPT_INVALID'):
        h.confirm(receipt={'custodian':'x','reference':'y','mac':'wrong'}, current_state=STATE)
    assert not (tmp_path/'witness.json').exists()
    r=receipt_for(w,custodian='independent',reference='receipt-01',custody_secret=C)
    assert h.confirm(receipt=r,current_state=STATE)=='CUSTODY_CONFIRMED'
    assert verify_witness(STATE,witness_path=tmp_path/'witness.json',secret=S)
    assert h.confirm(receipt=r,current_state=STATE)=='CUSTODY_CONFIRMED'

def test_stale_generation_fails_closed(tmp_path):
    h=handoff(tmp_path)
    w=h.prepare(STATE)
    r=receipt_for(w,custodian='independent',reference='receipt-01',custody_secret=C)
    with pytest.raises(ValueError, match='CUSTODY_GENERATION_STALE'):
        h.confirm(receipt=r,current_state={**STATE,'generation':3})
    assert h.status()=='PENDING_CUSTODY_ACK'

def test_pending_survives_restart_and_blocks_second_prepare(tmp_path):
    h=handoff(tmp_path)
    w=h.prepare(STATE)
    restarted=handoff(tmp_path)
    with pytest.raises(ValueError, match='CUSTODY_HANDOFF_PENDING'):
        restarted.prepare(STATE)
    r=receipt_for(w,custodian='independent',reference='receipt-01',custody_secret=C)
    assert restarted.confirm(receipt=r,current_state=STATE)=='CUSTODY_CONFIRMED'

def test_conflicting_receipt_rejected(tmp_path):
    h=handoff(tmp_path)
    w=h.prepare(STATE)
    r=receipt_for(w,custodian='independent',reference='receipt-01',custody_secret=C)
    h.confirm(receipt=r,current_state=STATE)
    r2=receipt_for(w,custodian='independent',reference='receipt-02',custody_secret=C)
    with pytest.raises(ValueError, match='CUSTODY_RECEIPT_CONFLICT'):
        h.confirm(receipt=r2,current_state=STATE)
