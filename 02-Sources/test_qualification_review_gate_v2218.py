import pytest
from fastapi import HTTPException
from qualification_review_gate_v2218 import enforce_review_gate
from qualification_review_security_v2217 import write_anchor

KEY=b'Z'*32

def test_anchor_and_roles(tmp_path):
    db=tmp_path/'review.db'; anchor=tmp_path/'head.json'
    write_anchor(db,anchor,KEY)
    identity={'subject':'auditor','roles':['qualification:approve','qualification:write']}
    assert enforce_review_gate(identity,review_db_path=db,anchor_path=anchor,secret=KEY)=='auditor'
    for roles in (['qualification:prepare','qualification:approve'],['qualification:write'],[]):
        with pytest.raises(HTTPException) as e:
            enforce_review_gate({'subject':'x','roles':roles},review_db_path=db,anchor_path=anchor,secret=KEY)
        assert e.value.status_code==403
    anchor.write_text('{"head":{},"hmac_sha256":"bad"}')
    with pytest.raises(HTTPException) as e:
        enforce_review_gate(identity,review_db_path=db,anchor_path=anchor,secret=KEY)
    assert e.value.status_code==503

def test_missing_anchor(tmp_path):
    with pytest.raises(HTTPException) as e:
        enforce_review_gate({'subject':'x','roles':['qualification:approve']},review_db_path=tmp_path/'db',anchor_path=None,secret=KEY)
    assert e.value.status_code==503
