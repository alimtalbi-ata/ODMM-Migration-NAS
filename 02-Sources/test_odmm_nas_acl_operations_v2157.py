import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_acl_history_v2149 import AuditHistory
from odmm_nas_acl_stream_v2154 import StreamingAuditHistory
from odmm_nas_acl_cas_v2152 import CASAnchoredHistory
from odmm_nas_acl_multiprocess_v2155 import SQLiteCASAnchor
from odmm_nas_acl_operations_v2157 import inspect_operations,attach_operations_diagnostics
from test_odmm_nas_acl_recovery_v2151 import signed

def fixture(tmp_path):
    h=StreamingAuditHistory(tmp_path/'history.db',b'k'*32)
    store=SQLiteCASAnchor(tmp_path/'anchor.db')
    a=CASAnchoredHistory(h,read_anchor=store.read,cas_anchor=store.cas,anchor_key=b'a'*32)
    a.bootstrap_empty()
    return h,store,a

def test_diagnostics_consistent(tmp_path):
    h,store,a=fixture(tmp_path)
    a.record(signed())
    r=inspect_operations(a)
    assert r['state']=='CONSISTENT' and r['records']==1 and r['head_seq']==1
    assert r['cutover_authorized'] is False and r['vendor_attested'] is False

def test_crash_window_blocks_until_explicit_reconciliation(tmp_path):
    h,store,a=fixture(tmp_path)
    # Fault injection: local SQLite commit succeeds, external CAS not executed.
    h.record(signed())
    assert a.inspect_recovery()['state']=='PENDING_ANCHOR'
    with pytest.raises(ValueError,match='AUDIT_NOT_CONSISTENT'):inspect_operations(a)
    with pytest.raises(ValueError):a.reconcile_explicit(expected_anchor_seq=0,expected_local_seq=1,approved=False)
    assert a.reconcile_explicit(expected_anchor_seq=0,expected_local_seq=1,approved=True)['state']=='RECOVERED'
    assert inspect_operations(a)['records']==1

def test_tamper_and_conflict_fail_closed(tmp_path):
    h,store,a=fixture(tmp_path)
    a.record(signed())
    with h._db() as db:db.execute("UPDATE acl_audit_history SET digest='bad' WHERE seq=1")
    with pytest.raises(ValueError):inspect_operations(a)

def test_api_auth_and_crash_status(tmp_path):
    h,store,a=fixture(tmp_path)
    app=FastAPI(); attach_operations_diagnostics(app,authorize=lambda req:req.headers.get('x-auth')=='yes',anchored_history=a)
    client=TestClient(app)
    assert client.get('/api/v1/operations/nas-acl-audit/diagnostics').status_code==403
    assert client.get('/api/v1/operations/nas-acl-audit/diagnostics',headers={'x-auth':'yes'}).status_code==200
    h.record(signed())
    resp=client.get('/api/v1/operations/nas-acl-audit/diagnostics',headers={'x-auth':'yes'})
    assert resp.status_code==503 and 'records' not in resp.json()

def test_sequence_gap_detected(tmp_path):
    h,store,a=fixture(tmp_path)
    a.record(signed());a.record(signed())
    with h._db() as db:db.execute('DELETE FROM acl_audit_history WHERE seq=1')
    with pytest.raises(ValueError):inspect_operations(a)
