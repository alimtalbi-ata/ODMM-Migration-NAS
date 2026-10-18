import json
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from qualification_review_security_v2217 import browser_write_guard,write_anchor,verify_anchor
from qualification_review_portal_v2216 import attach_review_portal
from qualification_dossier_v2214 import canonical_bytes
import hashlib

def test_browser_guard():
    app=FastAPI()
    @app.post('/write')
    def write(request: __import__('fastapi').Request):
        browser_write_guard(request,trusted_origins=['https://odmm.example'])
        return {'ok':True}
    c=TestClient(app)
    assert c.post('/write',headers={'origin':'https://evil.example','authorization':'Bearer x','content-type':'application/json'}).status_code==403
    assert c.post('/write',headers={'origin':'https://odmm.example','content-type':'application/json'}).status_code==403
    assert c.post('/write',headers={'origin':'https://odmm.example','authorization':'Bearer x','content-type':'text/plain'}).status_code==415
    assert c.post('/write',headers={'origin':'https://odmm.example','authorization':'Bearer x','content-type':'application/json'}).status_code==200

def test_anchor_detects_changes(tmp_path):
    from qualification_decisions_v2215 import append_review
    secret=b'k'*32; db=tmp_path/'db.sqlite'; anchor=tmp_path/'anchor.json'
    payload={'cutover_authorized':False,'review':{'decision':'PENDING_HUMAN_REVIEW'}}
    d={'payload':payload,'payload_sha256':hashlib.sha256(canonical_bytes(payload)).hexdigest(),'digest_algorithm':'SHA-256','signature_verified':False}
    write_anchor(db,anchor,secret)
    assert verify_anchor(db,anchor,secret)
    append_review(db,d,action='REJECT_REVIEW',reviewer='alice',reason='check',secret=secret)
    with pytest.raises(ValueError,match='CHANGED'):verify_anchor(db,anchor,secret)
    write_anchor(db,anchor,secret)
    assert verify_anchor(db,anchor,secret)
    data=json.loads(anchor.read_text());data['head']['count']=0;anchor.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='AUTHENTICATION'):verify_anchor(db,anchor,secret)
