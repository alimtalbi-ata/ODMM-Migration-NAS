"""Spawned HTTP clients and competing SQLite writes; synthetic single-host qualification.
Author: Abdelhalim Talbi.
"""
from concurrent.futures import ProcessPoolExecutor
import multiprocessing as mp
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_acl_history_v2149 import AuditHistory
from odmm_nas_acl_recovery_v2151 import RecoverableAnchoredHistory
from odmm_nas_acl_multiprocess_v2155 import SQLiteCASAnchor
from odmm_nas_acl_verified_snapshot_v2164 import attach_verified_snapshot
from test_odmm_nas_acl_snapshot_v2163 import KEY, document

ROUTE='/api/v1/operations/nas-acl-audit/verified-snapshot'


def _service(db_path, anchor_path):
    anchor=SQLiteCASAnchor(anchor_path)
    history=RecoverableAnchoredHistory(
        AuditHistory(db_path, KEY), read_anchor=anchor.read,
        write_anchor=lambda new: _cas_or_raise(anchor,new), anchor_key=KEY)
    app=FastAPI()
    attach_verified_snapshot(app, authorize=lambda request: request.headers.get('x-role')=='auditor', anchored_history=history)
    return app, history


def _cas_or_raise(anchor, new):
    if not anchor.cas(anchor.read(),new):
        raise RuntimeError('ANCHOR_CAS_CONFLICT')


def _http(args):
    db_path,anchor_path,role=args
    app,_=_service(db_path,anchor_path)
    with TestClient(app) as client:
        response=client.get(ROUTE,headers={'x-role':role})
    return response.status_code,response.json()


def _append_unanchored(db_path):
    return AuditHistory(db_path,KEY).record(document())


def test_spawned_http_readers_consistent(tmp_path):
    db=str(tmp_path/'history.sqlite'); anchor=str(tmp_path/'anchor.sqlite')
    _,history=_service(db,anchor)
    history.bootstrap_empty()
    history.record(document())
    with ProcessPoolExecutor(max_workers=4, mp_context=mp.get_context("spawn")) as pool:
        results=list(pool.map(_http,[(db,anchor,'auditor')]*12))
    assert len(results)==12
    assert all(status==200 and payload['verified_head_seq']==1 and payload['external_anchor_verified'] is True
               and payload['cutover_authorized'] is False for status,payload in results)


def test_spawned_http_fail_closed_after_competing_writer(tmp_path):
    db=str(tmp_path/'history.sqlite'); anchor=str(tmp_path/'anchor.sqlite')
    _,history=_service(db,anchor)
    history.bootstrap_empty()
    history.record(document())
    with ProcessPoolExecutor(max_workers=4, mp_context=mp.get_context("spawn")) as pool:
        assert pool.submit(_append_unanchored,db).result(timeout=30)==2
        results=list(pool.map(_http,[(db,anchor,'auditor')]*12))
    assert all(status==503 and payload['error']=='AUDIT_UNAVAILABLE' and
               payload['cutover_authorized'] is False for status,payload in results)
    assert SQLiteCASAnchor(anchor).read()['seq']==1  # no automatic reconciliation


def test_spawned_http_authorization(tmp_path):
    db=str(tmp_path/'history.sqlite'); anchor=str(tmp_path/'anchor.sqlite')
    _,history=_service(db,anchor)
    history.bootstrap_empty()
    history.record(document())
    with ProcessPoolExecutor(max_workers=2, mp_context=mp.get_context("spawn")) as pool:
        results=list(pool.map(_http,[(db,anchor,'reader')]*4))
    assert all(status==403 and payload['error']=='ACCESS_DENIED' for status,payload in results)
