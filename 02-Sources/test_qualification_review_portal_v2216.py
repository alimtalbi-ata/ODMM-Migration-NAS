import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from qualification_review_portal_v2216 import attach_review_portal

@pytest.fixture
def client(tmp_path, monkeypatch):
    import qualification_review_portal_v2216 as mod
    import qualification_decisions_v2215 as registry
    from qualification_dossier_v2214 import canonical_bytes
    import hashlib
    payload={'cutover_authorized':False,'review':{'decision':'PENDING_HUMAN_REVIEW'}}
    d={'payload':payload,'payload_sha256':hashlib.sha256(canonical_bytes(payload)).hexdigest(),'digest_algorithm':'SHA-256','signature_verified':False}
    monkeypatch.setattr(mod,'dossier',lambda *a,**k:d)
    app=FastAPI()
    attach_review_portal(app,authenticate=lambda r:{'subject':r.headers.get('x-user',''), 'roles':r.headers.get('x-roles','').split(',')},db_path='dummy',review_db_path=str(tmp_path/'reviews.db'),required_checks=['check'],secret=b'K'*32)
    return TestClient(app),d

def test_requires_auth(client):
    c,_=client
    assert c.get('/api/v1/operations/qualification-history/reviews').status_code==403

def test_read_and_write_roles(client):
    c,d=client
    path='/api/v1/operations/qualification-history/reviews'
    assert c.get(path,headers={'x-user':'reader','x-roles':'qualification:read'}).status_code==200
    assert c.post(path,headers={'x-user':'reader','x-roles':'qualification:read'},json={'action':'APPROVE_REVIEW','reason':'ok','dossier_sha256':d['payload_sha256']}).status_code==403
    h={'x-user':'approver','x-roles':'qualification:write','Idempotency-Key':'legacy-test-0001'}
    assert c.post(path,headers=h,json={'action':'APPROVE_REVIEW','reason':'verified','dossier_sha256':'0'*64}).status_code==409
    r=c.post(path,headers=h,json={'action':'APPROVE_REVIEW','reason':'verified','dossier_sha256':d['payload_sha256']})
    assert r.status_code==200,r.text
    assert r.json()['reviewer']=='approver'
    assert r.json()['cutover_authorized'] is False
    assert c.get(path,headers={'x-user':'reader','x-roles':'qualification:read'}).json()['review_status']=='APPROVED_REVIEW_ONLY'

def test_html_escapes(client):
    c,d=client
    c.post('/api/v1/operations/qualification-history/reviews',headers={'x-user':'<admin>','x-roles':'qualification:write','Idempotency-Key':'legacy-test-0002'},json={'action':'REJECT_REVIEW','reason':'<script>alert(1)</script>','dossier_sha256':d['payload_sha256']})
    r=c.get('/operations/qualification-history/reviews',headers={'x-user':'reader','x-roles':'qualification:read'})
    assert r.status_code==200 and '<script>' not in r.text and '&lt;script&gt;' in r.text
