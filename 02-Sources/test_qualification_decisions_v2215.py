import sqlite3
import pytest
from qualification_decisions_v2215 import append_review, review_status
from qualification_dossier_v2214 import canonical_bytes
import hashlib

KEY = b'a' * 32

def dossier(label='a'):
    p = {'review': {'decision': 'PENDING_HUMAN_REVIEW'}, 'cutover_authorized': False, 'label': label}
    return {'payload': p, 'payload_sha256': hashlib.sha256(canonical_bytes(p)).hexdigest(),
            'digest_algorithm': 'SHA-256', 'signature_verified': False}

def test_lifecycle(tmp_path):
    db = tmp_path/'review.db'; d = dossier()
    assert review_status(db,d,secret=KEY)['review_status'] == 'PENDING_HUMAN_REVIEW'
    append_review(db,d,action='APPROVE_REVIEW',reviewer='alice',reason='reviewed',secret=KEY,timestamp=1)
    assert review_status(db,d,secret=KEY)['review_status'] == 'APPROVED_REVIEW_ONLY'
    assert review_status(db,dossier('modified'),secret=KEY)['review_status'] == 'PENDING_HUMAN_REVIEW'
    with pytest.raises(ValueError,match='ALREADY_APPROVED'):
        append_review(db,d,action='APPROVE_REVIEW',reviewer='alice',reason='again',secret=KEY)
    append_review(db,d,action='REVOKE_REVIEW',reviewer='bob',reason='superseded',secret=KEY)
    s = review_status(db,d,secret=KEY)
    assert s['review_status'] == 'REVOKED' and not s['cutover_authorized'] and len(s['events']) == 2

def test_tamper_fail_closed(tmp_path):
    db=tmp_path/'review.db'; d=dossier()
    append_review(db,d,action='REJECT_REVIEW',reviewer='alice',reason='missing',secret=KEY)
    with sqlite3.connect(db) as con:
        con.execute("UPDATE review_events SET event_json=replace(event_json,'alice','mallory') WHERE seq=1")
    with pytest.raises(ValueError,match='INTEGRITY'):
        review_status(db,d,secret=KEY)

def test_wrong_key(tmp_path):
    db=tmp_path/'review.db'; d=dossier()
    append_review(db,d,action='REJECT_REVIEW',reviewer='alice',reason='missing',secret=KEY)
    with pytest.raises(ValueError,match='INTEGRITY'):
        review_status(db,d,secret=b'b'*32)

def test_invalid_inputs(tmp_path):
    db=tmp_path/'review.db'; d=dossier()
    with pytest.raises(ValueError,match='NO_ACTIVE'):
        append_review(db,d,action='REVOKE_REVIEW',reviewer='alice',reason='why',secret=KEY)
    with pytest.raises(ValueError,match='KEY'):
        review_status(db,d,secret=b'weak')
    with pytest.raises(ValueError,match='INVALID_DOSSIER'):
        append_review(db,{**d,'payload_sha256':'0'*64},action='APPROVE_REVIEW',reviewer='alice',reason='why',secret=KEY)
