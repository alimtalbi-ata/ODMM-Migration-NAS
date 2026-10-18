import pytest
from fastapi import HTTPException
from qualification_review_security_v2217 import write_anchor, verify_anchor
from qualification_review_rotation_v2219 import append_review_with_anchor
from qualification_decisions_v2215 import review_status
from qualification_dossier_v2214 import dossier
from qualification_history_v2205 import *

KEY=b'K'*32
IDENT={'subject':'reviewer','roles':['qualification:approve','qualification:write']}

def test_refresh_and_revoke(tmp_path, monkeypatch):
    import qualification_review_rotation_v2219 as m
    db=tmp_path/'reviews.db'; anchor=tmp_path/'anchor.json'
    # Existing dossier verification requires a valid signed dossier; use an existing dossier fixture if available.
    from qualification_dossier_v2214 import canonical_bytes
    import hashlib
    payload={'schema':'odmm.qualification.dossier.v2214','items':[]}
    # Test fail-closed precheck independent of dossier structure.
    with pytest.raises(HTTPException) as e:
        append_review_with_anchor(db, anchor, {}, identity=IDENT, action='APPROVE_REVIEW',reason='ok',secret=KEY)
    assert e.value.status_code==503
    write_anchor(db,anchor,KEY)
    assert verify_anchor(db,anchor,KEY)
    with pytest.raises(ValueError):
        append_review_with_anchor(db,anchor,{},identity=IDENT,action='APPROVE_REVIEW',reason='ok',secret=KEY)
    assert verify_anchor(db,anchor,KEY)

def test_bad_roles(tmp_path):
    db=tmp_path/'r.db'; a=tmp_path/'a.json'; write_anchor(db,a,KEY)
    with pytest.raises(HTTPException) as e:
        append_review_with_anchor(db,a,{},identity={'subject':'x','roles':['qualification:approve','qualification:prepare']},action='APPROVE_REVIEW',reason='x',secret=KEY)
    assert e.value.status_code==403
