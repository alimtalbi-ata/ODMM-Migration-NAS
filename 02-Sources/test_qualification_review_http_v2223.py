"""V222.3: HTTP conflict codes, replay and concurrent API requests."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
from fastapi import FastAPI
from fastapi.testclient import TestClient
from qualification_dossier_v2214 import canonical_bytes
from qualification_review_portal_v2216 import attach_review_portal
from qualification_decisions_v2215 import review_status

KEY=b'Z'*32
PATH='/api/v1/operations/qualification-history/reviews'

def setup(tmp_path, monkeypatch):
    import qualification_review_portal_v2216 as mod
    payload={'cutover_authorized':False,'review':{'decision':'PENDING_HUMAN_REVIEW'}}
    d={'payload':payload,'payload_sha256':hashlib.sha256(canonical_bytes(payload)).hexdigest(),'digest_algorithm':'SHA-256','signature_verified':False}
    monkeypatch.setattr(mod,'dossier',lambda *a,**k:d)
    app=FastAPI(); db=tmp_path/'reviews.sqlite'
    attach_review_portal(app,authenticate=lambda r:{'subject':r.headers.get('x-user','alice'),'roles':['qualification:write','qualification:read']},db_path='unused',review_db_path=str(db),required_checks=['test'],secret=KEY)
    return TestClient(app),d,db

def post(c,d,key,action='APPROVE_REVIEW',reason='reviewed'):
    return c.post(PATH,headers={'Idempotency-Key':key},json={'action':action,'reason':reason,'dossier_sha256':d['payload_sha256']})

def test_replay_and_conflict_http(tmp_path,monkeypatch):
    c,d,db=setup(tmp_path,monkeypatch)
    a=post(c,d,'request-0000001'); b=post(c,d,'request-0000001')
    assert a.status_code==b.status_code==200
    assert b.json()['idempotent_replay'] is True
    conflict=post(c,d,'request-0000001',reason='different')
    assert conflict.status_code==409 and conflict.json()['detail']=='IDEMPOTENCY_CONFLICT'
    other=post(c,d,'request-0000002')
    assert other.status_code==409 and other.json()['detail']=='REVIEW_STATE_CONFLICT'
    assert len(review_status(db,d,secret=KEY)['events'])==1

def test_parallel_http_same_key(tmp_path,monkeypatch):
    c,d,db=setup(tmp_path,monkeypatch)
    with ThreadPoolExecutor(max_workers=6) as pool:
        replies=list(pool.map(lambda _:post(c,d,'parallel-000001'),range(12)))
    assert all(r.status_code==200 for r in replies),[(r.status_code,r.text) for r in replies]
    assert len(review_status(db,d,secret=KEY)['events'])==1

def test_parallel_http_distinct_keys(tmp_path,monkeypatch):
    c,d,db=setup(tmp_path,monkeypatch)
    with ThreadPoolExecutor(max_workers=6) as pool:
        replies=list(pool.map(lambda i:post(c,d,f'parallel-{i:08d}'),range(8)))
    assert sum(r.status_code==200 for r in replies)==1
    assert all(r.status_code in (200,409) for r in replies)
    assert len(review_status(db,d,secret=KEY)['events'])==1
