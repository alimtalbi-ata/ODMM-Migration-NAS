import tempfile
from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_nas_acl_history_v2149 import AuditHistory
from odmm_nas_acl_cas_v2152 import CASAnchoredHistory,attach_acl_recovery_status
from test_odmm_nas_acl_recovery_v2151 import signed

def fixture():
    tmp=tempfile.TemporaryDirectory()
    h=AuditHistory(Path(tmp.name)/'audit.db',b'k'*32)
    store={'value':None,'conflict':False,'calls':0}
    def read():return store['value']
    def cas(old,new):
        store['calls']+=1
        if store['conflict'] or store['value']!=old:return False
        store['value']=new
        return True
    a=CASAnchoredHistory(h,read_anchor=read,cas_anchor=cas,anchor_key=b'a'*32)
    a.bootstrap_empty()
    return tmp,h,a,store

def test_bootstrap_and_record():
    tmp,h,a,s=fixture()
    try:
        assert a.verify()
        assert a.record(signed())==1
        assert a.inspect_recovery()['state']=='CONSISTENT'
        assert s['calls']==2
    finally:tmp.cleanup()

def test_conflict_fails_closed_then_explicit_recovery():
    tmp,h,a,s=fixture()
    try:
        s['conflict']=True
        with pytest.raises(ValueError,match='CAS_CONFLICT'):a.record(signed())
        assert a.inspect_recovery()['state']=='PENDING_ANCHOR'
        assert not a.verify()
        with pytest.raises(ValueError):a.record(signed())
        s['conflict']=False
        with pytest.raises(ValueError):a.reconcile_explicit(expected_anchor_seq=0,expected_local_seq=1)
        assert a.reconcile_explicit(expected_anchor_seq=0,expected_local_seq=1,approved=True)['state']=='RECOVERED'
    finally:tmp.cleanup()

def test_stale_cas_rejected():
    tmp,h,a,s=fixture()
    try:
        original=s['value'].copy()
        assert a.record(signed())==1
        assert s['value']!=original
        assert a.cas_anchor(original,a._seal(a._checkpoint())) is False
    finally:tmp.cleanup()

def test_no_bootstrap_over_existing():
    tmp,h,a,s=fixture()
    try:
        with pytest.raises(ValueError):a.bootstrap_empty()
    finally:tmp.cleanup()

def test_auth_and_sanitized_status():
    tmp,h,a,s=fixture()
    try:
        app=FastAPI()
        attach_acl_recovery_status(app,authorize=lambda request:request.headers.get('x-test-auth')=='yes',anchored_history=a)
        client=TestClient(app)
        path='/api/v1/operations/nas-acl-audit/recovery/status'
        assert client.get(path).status_code==403
        r=client.get(path,headers={'x-test-auth':'yes'})
        assert r.status_code==200 and r.json()=={'state':'CONSISTENT','recoverable':False,'cutover_authorized':False}
        assert 'no-store' in r.headers['cache-control']
        s['conflict']=True
        with pytest.raises(ValueError):a.record(signed())
        r=client.get(path,headers={'x-test-auth':'yes'})
        assert r.status_code==503 and r.json()['state']=='PENDING_ANCHOR'
        assert 'chain_mac' not in r.text
    finally:tmp.cleanup()

def test_composition_factory_importable():
    from odmm_operations_app import create_nas_acl_cas_operations_app
    assert callable(create_nas_acl_cas_operations_app)
