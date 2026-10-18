import sqlite3
from fastapi import FastAPI
from fastapi.testclient import TestClient
from qualification_history_v2205 import SCHEMA
from qualification_comparison_v2208 import attach_qualification_comparison
import json
import pytest

@pytest.fixture
def client(tmp_path):
    db=tmp_path/'history.sqlite'
    with sqlite3.connect(db) as con:
        con.execute(SCHEMA)
        for i, checks, failures in [(1,{'a':True,'b':False},[]),(2,{'a':False,'b':True},['new issue'])]:
            con.execute('INSERT INTO runs(recorded_at,evidence_sha256,status,browser_status,checks_json,failures_json,screenshots_json,windows_qualified) VALUES (?,?,?,?,?,?,?,0)',
                        (f'2026-10-16T00:00:0{i}Z',str(i)*64,'FAIL','FAIL',json.dumps(checks),json.dumps(failures),'[]'))
    app=FastAPI()
    attach_qualification_comparison(app,authorize=lambda request: request.headers.get('x-token')=='ok',db_path=db)
    return TestClient(app)

def test_selector_and_export(client):
    h={'x-token':'ok'}
    r=client.get('/operations/qualification-history/compare-select',headers=h)
    assert r.status_code==200 and 'Régressions (1)' in r.text and 'Améliorations (1)' in r.text
    r=client.get('/api/v1/operations/qualification-history/comparison-report?older=1&newer=2',headers=h)
    assert r.status_code==200 and r.json()['counts']=={'regressions':1,'improvements':1,'new_failures':1}
    assert r.json()['cutover_authorized'] is False

def test_auth_first(client):
    assert client.get('/operations/qualification-history/compare-select').status_code==403
    assert client.get('/api/v1/operations/qualification-history/comparison-report?older=1&newer=2').status_code==403

def test_order_and_selection(client):
    h={'x-token':'ok'}
    assert client.get('/api/v1/operations/qualification-history/comparison-report?older=2&newer=1',headers=h).status_code==422
    assert client.get('/operations/qualification-history/compare-select?older=1&newer=99',headers=h).status_code==422
    assert client.get('/operations/qualification-history/compare-select?older=1',headers=h).status_code==422

def test_escape(tmp_path):
    db=tmp_path/'db.sqlite'
    with sqlite3.connect(db) as con:
        con.execute(SCHEMA)
        for i in (1,2):
            con.execute('INSERT INTO runs(recorded_at,evidence_sha256,status,browser_status,checks_json,failures_json,screenshots_json,windows_qualified) VALUES (?,?,?,?,?,?,?,0)',
                        ('<script>alert(1)</script>',str(i)*64,'FAIL','FAIL','{}','[]','[]'))
    app=FastAPI();attach_qualification_comparison(app,authorize=lambda _:True,db_path=db)
    text=TestClient(app).get('/operations/qualification-history/compare-select').text
    assert '<script>alert' not in text and '&lt;script&gt;' in text
