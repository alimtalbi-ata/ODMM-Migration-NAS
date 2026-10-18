import threading
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from test_odmm_nas_acl_cas_v2152 import fixture
from test_odmm_nas_acl_recovery_v2151 import signed
from odmm_nas_acl_scale_v2153 import audit_overview, benchmark_pages, attach_acl_scale_status


def test_overview_and_pagination():
    tmp,h,a,store=fixture()
    try:
        for _ in range(120): a.record(signed())
        assert audit_overview(a)['records']==120
        assert len(a.page(limit=100)['items'])==100
        cursor=a.page(limit=100)['next_cursor']
        assert len(a.page(cursor=cursor,limit=100)['items'])==20
        b=benchmark_pages(a,iterations=2,page_size=25)
        assert b['rows_read']==50 and b['environment']=='synthetic-local'
    finally:tmp.cleanup()


def test_concurrent_cas_serializes_within_process():
    tmp,h,a,store=fixture()
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda _:a.record(signed()),range(24)))
        assert sorted(results)==list(range(1,25))
        assert a.verify() and audit_overview(a)['records']==24
    finally:tmp.cleanup()


def test_conflict_blocks_overview_and_benchmark():
    tmp,h,a,store=fixture()
    try:
        store['conflict']=True
        with pytest.raises(ValueError):a.record(signed())
        with pytest.raises(ValueError):audit_overview(a)
        with pytest.raises(ValueError):benchmark_pages(a)
    finally:tmp.cleanup()


def test_authenticated_status_and_sanitization():
    tmp,h,a,store=fixture()
    try:
        app=FastAPI()
        attach_acl_scale_status(app,authorize=lambda r:r.headers.get('x-token')=='ok',anchored_history=a)
        client=TestClient(app); url='/api/v1/operations/nas-acl-audit/scale/overview'
        assert client.get(url).status_code==403
        r=client.get(url,headers={'x-token':'ok'})
        assert r.status_code==200 and r.json()['records']==0
        assert 'no-store' in r.headers['cache-control']
        assert 'principal' not in r.text and 'path' not in r.text
        store['conflict']=True
        with pytest.raises(ValueError):a.record(signed())
        assert client.get(url,headers={'x-token':'ok'}).status_code==503
    finally:tmp.cleanup()

@pytest.mark.parametrize('iterations,page_size',[(0,10),(10001,10),(1,0),(1,101),(True,1)])
def test_invalid_benchmark_bounds(iterations,page_size):
    tmp,h,a,store=fixture()
    try:
        with pytest.raises(ValueError):benchmark_pages(a,iterations=iterations,page_size=page_size)
    finally:tmp.cleanup()
