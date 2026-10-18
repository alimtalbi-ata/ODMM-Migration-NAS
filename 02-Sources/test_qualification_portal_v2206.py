import sqlite3
from fastapi import FastAPI
from fastapi.testclient import TestClient
from qualification_history_v2205 import SCHEMA
from qualification_portal_v2206 import attach_qualification_history

def test_routes(tmp_path):
    db=tmp_path/'q.db'
    with sqlite3.connect(db) as c:
        c.execute(SCHEMA)
        for i in range(2):
            c.execute('INSERT INTO runs(recorded_at,evidence_sha256,status,browser_status,checks_json,failures_json,screenshots_json,windows_qualified) VALUES (?,?,?,?,?,?,?,0)',(f'2026-10-16T10:0{i}:00Z',str(i),'PASS','PASS','{"navigation":true}' if i==0 else '{"navigation":false}', '[]','[]'))
    app=FastAPI();attach_qualification_history(app,authorize=lambda r:r.headers.get('x-auth')=='yes',db_path=db)
    c=TestClient(app)
    assert c.get('/operations/qualification-history').status_code==403
    assert c.get('/api/v1/operations/qualification-history').status_code==403
    h={'x-auth':'yes'}
    r=c.get('/operations/qualification-history',headers=h); assert r.status_code==200 and 'Historique' in r.text and 'Content-Security-Policy' in r.headers
    assert c.get('/api/v1/operations/qualification-history',headers=h).json()['windows_qualified'] is False
    assert c.get('/api/v1/operations/qualification-history/compare?older=1&newer=2',headers=h).json()['regressions']==['navigation']
    assert c.get('/api/v1/operations/qualification-history?limit=101',headers=h).status_code==422
    assert c.get('/api/v1/operations/qualification-history/compare?older=1&newer=1',headers=h).status_code==422
    assert c.get('/api/v1/operations/qualification-history/compare?older=1&newer=9',headers=h).status_code==503
    db.unlink()
    assert c.get('/operations/qualification-history',headers=h).status_code==503

def test_requires_authorization(tmp_path):
    import pytest
    with pytest.raises(ValueError): attach_qualification_history(FastAPI(),authorize=None,db_path=tmp_path/'db')
