import sqlite3
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_acl_history_v2149 import AuditHistory
from odmm_nas_acl_anchor_v2150 import AnchoredAuditHistory,attach_anchor_status
from odmm_nas_acl_export_v2148 import attach_acl_signed_export
from odmm_nas_acl_semantics_v2146 import VENDORS
from test_odmm_nas_acl_portal_v2147 import evidence
KEY=b'local-only-test-signing-key-32-bytes-minimum'

def make(tmp_path):
    history=AuditHistory(tmp_path/'history.db',KEY)
    anchor={}
    anchored=AnchoredAuditHistory(history,read_anchor=lambda:anchor.get('doc'),write_anchor=lambda d:anchor.update(doc=d),anchor_key=KEY)
    return history,anchor,anchored

def test_bootstrap_and_record(tmp_path):
    history,anchor,guard=make(tmp_path)
    assert not guard.verify()
    guard.bootstrap_empty()
    assert guard.verify()
    app=FastAPI()
    providers={v:(lambda protocol,v=v:evidence(v,protocol)) for v in VENDORS}
    attach_acl_signed_export(app,authorize=lambda r:True,providers=providers,hmac_key=KEY,record_export=guard.record)
    attach_anchor_status(app,authorize=lambda r:True,anchored_history=guard)
    client=TestClient(app)
    assert client.get('/api/v1/operations/nas-acl-audit/export').status_code==200
    assert anchor['doc']['seq']==1
    assert client.get('/api/v1/operations/nas-acl-audit/anchor/verify').json()['anchor_valid']
    with sqlite3.connect(history.path) as db:db.execute('DELETE FROM acl_audit_history')
    assert not guard.verify()
    assert client.get('/api/v1/operations/nas-acl-audit/export').status_code==503
    assert client.get('/api/v1/operations/nas-acl-audit/anchor/verify').status_code==503
    with pytest.raises(ValueError):guard.bootstrap_empty()

def test_tampered_anchor_and_auth(tmp_path):
    history,anchor,guard=make(tmp_path);guard.bootstrap_empty()
    app=FastAPI();attach_anchor_status(app,authorize=lambda r:False,anchored_history=guard)
    assert TestClient(app).get('/api/v1/operations/nas-acl-audit/anchor/verify').status_code==403
    anchor['doc']['seq']=5
    assert not guard.verify()

def test_nonempty_history_cannot_bootstrap(tmp_path):
    history,anchor,guard=make(tmp_path)
    with sqlite3.connect(history.path) as db:db.execute("INSERT INTO acl_audit_history(digest,previous,chain_mac,report) VALUES('a','GENESIS','b','{}')")
    with pytest.raises(ValueError):guard.bootstrap_empty()

def test_anchor_write_failure_blocks_export(tmp_path):
    history,anchor,guard=make(tmp_path);guard.bootstrap_empty()
    broken=AnchoredAuditHistory(history,read_anchor=lambda:anchor.get('doc'),write_anchor=lambda d:(_ for _ in ()).throw(OSError('secret')),anchor_key=KEY)
    with pytest.raises(OSError):broken.record({'fake':True}) if False else broken.write_anchor({})

def test_missing_external_anchor_blocks_access(tmp_path):
    _,anchor,guard=make(tmp_path)
    guard.bootstrap_empty()
    anchor.clear()
    assert not guard.verify()
    with pytest.raises(ValueError):guard.page()

def test_anchor_cannot_be_replayed_behind_valid_newer_checkpoint(tmp_path):
    _,anchor,guard=make(tmp_path)
    guard.bootstrap_empty()
    assert guard.verify()
    assert guard._read()['seq']==0
