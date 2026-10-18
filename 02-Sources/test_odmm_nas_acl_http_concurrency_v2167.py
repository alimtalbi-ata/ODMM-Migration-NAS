"""Concurrent HTTP reads against SQLite-backed ACL history; local-only qualification.
Author: Abdelhalim Talbi.
"""
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_acl_recovery_v2151 import RecoverableAnchoredHistory
from odmm_nas_acl_history_v2149 import AuditHistory
from odmm_nas_acl_verified_snapshot_v2164 import attach_verified_snapshot
from test_odmm_nas_acl_snapshot_v2163 import KEY, document


def _app(tmp_path):
    anchor = [None]
    def read(): return anchor[0]
    def cas(expected, replacement):
        if anchor[0] != expected: return False
        anchor[0] = replacement
        return True
    history = RecoverableAnchoredHistory(AuditHistory(tmp_path/'history.sqlite', KEY), read_anchor=read, write_anchor=lambda doc: anchor.__setitem__(0, doc), anchor_key=KEY)
    history.bootstrap_empty()
    history.record(document())
    app = FastAPI()
    attach_verified_snapshot(app, authorize=lambda request: request.headers.get('x-role') == 'auditor', anchored_history=history)
    return app, history, anchor


def test_parallel_http_verified_snapshot(tmp_path):
    app, history, anchor = _app(tmp_path)
    def query(i):
        with TestClient(app) as client:
            r=client.get('/api/v1/operations/nas-acl-audit/verified-snapshot', headers={'x-role':'auditor'})
            return r.status_code, r.json()
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses=list(pool.map(query, range(24)))
    assert all(status==200 and data['external_anchor_verified'] is True and data['verified_head_seq']==1 for status,data in responses)


def test_parallel_http_fail_closed_after_anchor_loss(tmp_path):
    app, history, anchor = _app(tmp_path)
    anchor[0] = None
    def query(i):
        with TestClient(app) as client:
            return client.get('/api/v1/operations/nas-acl-audit/verified-snapshot', headers={'x-role':'auditor'}).status_code
    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses=list(pool.map(query, range(24)))
    assert statuses == [503]*24
