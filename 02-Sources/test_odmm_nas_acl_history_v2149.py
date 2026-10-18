import sqlite3
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_acl_history_v2149 import AuditHistory,attach_acl_history
from odmm_nas_acl_export_v2148 import attach_acl_signed_export
from odmm_nas_acl_semantics_v2146 import VENDORS
from test_odmm_nas_acl_portal_v2147 import evidence
KEY=b'local-only-test-signing-key-32-bytes-minimum'

def setup(tmp_path, allowed=True):
    app=FastAPI(); history=AuditHistory(tmp_path/'audit.db',KEY)
    providers={v:(lambda protocol,v=v:evidence(v,protocol)) for v in VENDORS}
    attach_acl_signed_export(app,authorize=lambda r:allowed,providers=providers,hmac_key=KEY,record_export=history.record)
    attach_acl_history(app,authorize=lambda r:allowed,history=history)
    return TestClient(app),history

def test_history_and_pagination(tmp_path):
    client,history=setup(tmp_path)
    for i in range(3):assert client.get('/api/v1/operations/nas-acl-audit/export').status_code==200
    first=client.get('/api/v1/operations/nas-acl-audit/history?limit=2').json()
    assert len(first['items'])==2 and first['next_cursor']==2
    second=client.get('/api/v1/operations/nas-acl-audit/history?cursor=2&limit=2').json()
    assert len(second['items'])==1 and second['next_cursor'] is None
    assert history.verify_chain()
    assert client.get('/api/v1/operations/nas-acl-audit/history/verify').json()['valid'] is True
    assert '/private/customer' not in str(first) and 'secret-user' not in str(first)

def test_auth_and_bounds(tmp_path):
    client,_=setup(tmp_path,False)
    assert client.get('/api/v1/operations/nas-acl-audit/history').status_code==403
    assert client.get('/api/v1/operations/nas-acl-audit/export').status_code==403
    client,_=setup(tmp_path)
    assert client.get('/api/v1/operations/nas-acl-audit/history?limit=101').status_code==400
    assert client.get('/api/v1/operations/nas-acl-audit/history?cursor=-1').status_code==400

def test_tamper_detected(tmp_path):
    client,history=setup(tmp_path)
    assert client.get('/api/v1/operations/nas-acl-audit/export').status_code==200
    with sqlite3.connect(history.path) as db:db.execute("UPDATE acl_audit_history SET digest='falsified' WHERE seq=1")
    assert not history.verify_chain()
    assert client.get('/api/v1/operations/nas-acl-audit/history/verify').status_code==503

def test_no_persist_no_export(tmp_path):
    app=FastAPI()
    providers={v:(lambda protocol,v=v:evidence(v,protocol)) for v in VENDORS}
    attach_acl_signed_export(app,authorize=lambda r:True,providers=providers,hmac_key=KEY,record_export=lambda document: (_ for _ in ()).throw(RuntimeError('private secret')))
    response=TestClient(app).get('/api/v1/operations/nas-acl-audit/export')
    assert response.status_code==503 and 'private secret' not in response.text
