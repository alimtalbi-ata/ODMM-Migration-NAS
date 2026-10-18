import json
import sqlite3
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from qualification_history_v2205 import SCHEMA
from qualification_trends_v2211 import trends, attach_qualification_trends

@pytest.fixture
def db(tmp_path):
    p=tmp_path/'history.db'
    with sqlite3.connect(p) as c:
        c.execute(SCHEMA)
        for i, checks in enumerate(({'auth':True,'navigation':False},{'auth':False,'navigation':True},{'auth':True,'navigation':True}),1):
            c.execute('INSERT INTO runs(recorded_at,evidence_sha256,status,browser_status,checks_json,failures_json,screenshots_json,windows_qualified) VALUES (?,?,?,?,?,?,?,0)',(f'2026-10-16T10:0{i}:00Z',f'{i:064x}','FAIL','FAIL',json.dumps(checks),'[]','[]'))
    return p

def test_trends(db):
    r=trends(db)
    assert r['summary']=={'runs':3,'regressions':1,'improvements':2,'open_failures':0}
    assert r['controls'][0]['severity']=='CRITICAL'
    assert not r['cutover_authorized']

def test_invalid_limit(db):
    with pytest.raises(ValueError): trends(db,1)

def test_tamper_fails_closed(db):
    with sqlite3.connect(db) as c: c.execute('UPDATE runs SET checks_json=? WHERE id=1', ('{"auth": "invalid"}',))
    with pytest.raises(HTTPException) as err: trends(db)
    assert err.value.status_code==503

def test_routes_and_authorization(db):
    app=FastAPI()
    attach_qualification_trends(app,authorize=lambda r:r.headers.get('x-test-auth')=='yes',db_path=db)
    c=TestClient(app)
    assert c.get('/api/v1/operations/qualification-history/trends.json').status_code==403
    response=c.get('/api/v1/operations/qualification-history/trends.json',headers={'x-test-auth':'yes'})
    assert response.status_code==200 and response.json()['summary']['runs']==3
    response=c.get('/operations/qualification-history/trends',headers={'x-test-auth':'yes'})
    assert response.status_code==200 and 'Content-Security-Policy' in response.headers

def test_html_escape(db):
    with sqlite3.connect(db) as c:
        checks={'<script>alert(1)</script>':True}
        c.execute('UPDATE runs SET checks_json=? WHERE id=3',(json.dumps(checks),))
    app=FastAPI();attach_qualification_trends(app,authorize=lambda r:True,db_path=db)
    page=TestClient(app).get('/operations/qualification-history/trends')
    assert '<script>' not in page.text and '&lt;script&gt;' in page.text
