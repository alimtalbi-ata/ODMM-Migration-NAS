import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_acl_verified_page_v2158 import verified_page,attach_verified_page
from test_odmm_nas_acl_operations_v2157 import fixture
from test_odmm_nas_acl_recovery_v2151 import signed


def test_pages_are_bounded_and_cursor_stable(tmp_path):
    h,store,a=fixture(tmp_path)
    for _ in range(4):a.record(signed())
    p=verified_page(a,limit=2)
    assert [x['seq'] for x in p['items']]==[1,2]
    assert p['next_cursor']==2 and p['cutover_authorized'] is False
    p2=verified_page(a,cursor=p['next_cursor'],limit=2)
    assert [x['seq'] for x in p2['items']]==[3,4]
    assert p2['next_cursor'] is None

@pytest.mark.parametrize('cursor,limit',[(-1,1),(0,0),(0,101),(True,5),(0,False)])
def test_invalid_page(tmp_path,cursor,limit):
    _,_,a=fixture(tmp_path)
    with pytest.raises(ValueError,match='INVALID_PAGE'):verified_page(a,cursor=cursor,limit=limit)

def test_pending_anchor_blocks_all_pages(tmp_path):
    h,store,a=fixture(tmp_path)
    h.record(signed())
    with pytest.raises(RuntimeError,match='AUDIT_UNAVAILABLE'):verified_page(a)

def test_corruption_blocks_all_pages(tmp_path):
    h,store,a=fixture(tmp_path)
    a.record(signed())
    with h._db() as db:db.execute("UPDATE acl_audit_history SET digest='corrupt' WHERE seq=1")
    with pytest.raises(RuntimeError,match='AUDIT_UNAVAILABLE'):verified_page(a)

def test_http_auth_and_safe_errors(tmp_path):
    h,store,a=fixture(tmp_path)
    app=FastAPI()
    attach_verified_page(app,authorize=lambda r:r.headers.get('x-auth')=='yes',anchored_history=a)
    c=TestClient(app)
    url='/api/v1/operations/nas-acl-audit/verified-page'
    assert c.get(url).status_code==403
    assert c.get(url,headers={'x-auth':'yes'}).status_code==200
    assert c.get(url+'?limit=101',headers={'x-auth':'yes'}).status_code==400
    h.record(signed())
    r=c.get(url,headers={'x-auth':'yes'})
    assert r.status_code==503 and 'items' not in r.json()
