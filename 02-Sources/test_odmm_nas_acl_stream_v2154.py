import sqlite3
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest
from test_odmm_nas_acl_cas_v2152 import fixture
from test_odmm_nas_acl_recovery_v2151 import signed
from odmm_nas_acl_stream_v2154 import StreamingAuditHistory, inspect_history_performance, attach_acl_stream_status

def test_streaming_large_and_batches(tmp_path):
    h=StreamingAuditHistory(tmp_path/'a.sqlite',b'k'*32)
    for _ in range(135):h.record(signed())
    for n in (1,2,7,256,4096):assert h.verify_chain(batch_size=n)
    assert inspect_history_performance(h,batch_size=7)['records']==135
    for n in (0,4097,True):
        with pytest.raises(ValueError):h.verify_chain(batch_size=n)

def test_deleted_middle_record_detected(tmp_path):
    h=StreamingAuditHistory(tmp_path/'a.sqlite',b'k'*32)
    for _ in range(4):h.record(signed())
    with h._db() as db:db.execute('DELETE FROM acl_audit_history WHERE seq=2')
    assert h.verify_chain(batch_size=1) is False

def test_corrupt_report_detected(tmp_path):
    h=StreamingAuditHistory(tmp_path/'a.sqlite',b'k'*32)
    h.record(signed())
    with h._db() as db:db.execute("UPDATE acl_audit_history SET report='not json' WHERE seq=1")
    assert not h.verify_chain()

def test_authenticated_integrity_endpoint():
    tmp,h,a,store=fixture()
    try:
        a.history=StreamingAuditHistory(h.path,h.key)
        app=FastAPI()
        attach_acl_stream_status(app,authorize=lambda r:r.headers.get('x-token')=='yes',anchored_history=a)
        client=TestClient(app);url='/api/v1/operations/nas-acl-audit/scale/integrity'
        assert client.get(url).status_code==403
        good=client.get(url,headers={'x-token':'yes'})
        assert good.status_code==200 and good.json()['records']==0
        assert 'no-store' in good.headers['cache-control']
        assert 'principal' not in good.text
        store['conflict']=True
        with pytest.raises(ValueError):a.record(signed())
        assert client.get(url,headers={'x-token':'yes'}).status_code==503
    finally:tmp.cleanup()
