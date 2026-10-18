"""V222.4: simulate SQLite failure and interruption/retry semantics."""
import sqlite3
import pytest
from fastapi import HTTPException
from qualification_review_resilience_v2224 import map_review_storage_error
from qualification_review_coordination_v2220 import append_review_coordinated, recover_anchor_supervised
from qualification_review_security_v2217 import write_anchor, review_head, verify_anchor
from qualification_decisions_v2215 import append_review, review_status
from test_qualification_review_http_v2223 import setup, post, KEY


def test_sqlite_error_mapped():
    err = map_review_storage_error(sqlite3.OperationalError('sensitive db path'))
    assert err.status_code == 503
    assert 'sensitive' not in err.detail


def test_os_error_mapped():
    assert map_review_storage_error(OSError('disk full')).status_code == 503
    assert map_review_storage_error(ValueError('invalid payload')) is None


def test_http_sqlite_failure_returns_503(tmp_path, monkeypatch):
    client, d, db = setup(tmp_path, monkeypatch)
    import qualification_review_portal_v2216 as mod
    def broken(*a, **kw):
        raise sqlite3.OperationalError('disk I/O error')
    monkeypatch.setattr(mod, 'append_http_review', broken)
    r = post(client, d, 'storage-0000001')
    assert r.status_code == 503
    assert r.json()['detail'] == 'REVIEW_STORAGE_UNAVAILABLE_RECONCILE_BEFORE_RETRY'


def test_http_os_failure_returns_503(tmp_path, monkeypatch):
    client, d, db = setup(tmp_path, monkeypatch)
    import qualification_review_portal_v2216 as mod
    monkeypatch.setattr(mod, 'append_http_review', lambda *a, **kw: (_ for _ in ()).throw(OSError('no space')))
    assert post(client, d, 'storage-0000002').status_code == 503


def test_commit_before_anchor_failure_requires_recovery(tmp_path, monkeypatch):
    client, d, db = setup(tmp_path, monkeypatch)
    anchor = tmp_path/'anchor.json'
    write_anchor(db, anchor, KEY)
    identity={'subject':'alice','roles':['qualification:approve','qualification:write']}
    import qualification_review_coordination_v2220 as mod
    real_write = mod.write_anchor
    monkeypatch.setattr(mod, 'write_anchor', lambda *a, **kw: (_ for _ in ()).throw(OSError('disk full')))
    with pytest.raises(HTTPException) as exc:
        append_review_coordinated(db, anchor, d, identity=identity, action='APPROVE_REVIEW', reason='approved', secret=KEY, request_id='failure-00001')
    assert exc.value.status_code == 503
    assert len(review_status(db,d,secret=KEY)['events']) == 1
    with pytest.raises(HTTPException):
        append_review_coordinated(db, anchor, d, identity=identity, action='APPROVE_REVIEW', reason='approved', secret=KEY, request_id='failure-00001')
    monkeypatch.setattr(mod, 'write_anchor', real_write)
    head = review_head(db,KEY)
    with pytest.raises(ValueError):
        recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac='WRONG',expected_count=head['count'])
    result = recover_anchor_supervised(db,anchor,secret=KEY,expected_head_mac=head['head_mac'],expected_count=head['count'])
    assert result['cutover_authorized'] is False
    assert verify_anchor(db,anchor,KEY)
    replay = append_review_coordinated(db, anchor, d, identity=identity, action='APPROVE_REVIEW', reason='approved', secret=KEY, request_id='failure-00001')
    assert replay['idempotent_replay'] is True
    assert len(review_status(db,d,secret=KEY)['events']) == 1
