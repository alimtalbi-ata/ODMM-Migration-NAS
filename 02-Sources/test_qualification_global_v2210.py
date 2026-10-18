import json
import sqlite3
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from qualification_history_v2205 import SCHEMA
from qualification_global_v2210 import attach_qualification_global

@pytest.fixture
def client(tmp_path):
    db=tmp_path/'runs.sqlite'
    with sqlite3.connect(db) as con:
        con.execute(SCHEMA)
        for i,checks in ((1,{'pass':True,'fail':False,'<script>':True}),(2,{'pass':True,'fail':True,'<script>':False})):
            con.execute('INSERT INTO runs(recorded_at,evidence_sha256,status,browser_status,checks_json,failures_json,screenshots_json,windows_qualified) VALUES (?,?,?,?,?,?,?,0)',(str(i),format(i,'064x'),'FAIL','FAIL',json.dumps(checks),'[]','[]'))
    app=FastAPI();attach_qualification_global(app,authorize=lambda r:r.headers.get('x-token')=='yes',db_path=db)
    return TestClient(app)

def test_denied(client):
    assert client.get('/operations/qualification-history/global?older=1&newer=2').status_code==403
    assert client.get('/api/v1/operations/qualification-history/global.json?older=1&newer=2').status_code==403

def test_report(client):
    r=client.get('/api/v1/operations/qualification-history/global.json?older=1&newer=2',headers={'x-token':'yes'})
    assert r.status_code==200
    data=r.json()
    assert data['counts']['REGRESSION']==1 and data['counts']['IMPROVEMENT']==1
    assert data['verdict']=='REVIEW_REQUIRED' and data['cutover_authorized'] is False
    assert r.headers['cache-control']=='no-store'

def test_html_escaped(client):
    r=client.get('/operations/qualification-history/global?older=1&newer=2',headers={'x-token':'yes'})
    assert r.status_code==200 and '&lt;script&gt;' in r.text and '<script>' not in r.text
    assert 'content-security-policy' in r.headers

def test_order_and_missing(client):
    h={'x-token':'yes'}
    assert client.get('/api/v1/operations/qualification-history/global.json?older=2&newer=1',headers=h).status_code==422
    assert client.get('/api/v1/operations/qualification-history/global.json?older=1&newer=99',headers=h).status_code==404

