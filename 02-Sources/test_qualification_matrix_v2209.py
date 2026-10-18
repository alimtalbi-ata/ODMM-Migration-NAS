import csv
import io
import json
import sqlite3
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from qualification_history_v2205 import SCHEMA
from qualification_matrix_v2209 import attach_qualification_matrix

@pytest.fixture
def client(tmp_path):
    db=tmp_path/'q.sqlite'
    with sqlite3.connect(db) as con:
        con.execute(SCHEMA)
        for i,checks in [(1,{'ok':True,'bad':False,'=EVIL()':True,'removed':True}), (2,{'ok':True,'bad':True,'=EVIL()':False,'added':False})]:
            con.execute('INSERT INTO runs(recorded_at,evidence_sha256,status,browser_status,checks_json,failures_json,screenshots_json,windows_qualified) VALUES (?,?,?,?,?,?,?,0)',(str(i),str(i)*64,'FAIL','FAIL',json.dumps(checks),'[]','[]'))
    app=FastAPI();attach_qualification_matrix(app,authorize=lambda r:r.headers.get('x-token')=='yes',db_path=db)
    return TestClient(app)

def test_auth(client):
    assert client.get('/operations/qualification-history/matrix?older=1&newer=2').status_code==403
    assert client.get('/api/v1/operations/qualification-history/matrix.csv?older=1&newer=2').status_code==403

def test_matrix(client):
    r=client.get('/operations/qualification-history/matrix?older=1&newer=2',headers={'x-token':'yes'})
    assert r.status_code==200 and 'REGRESSION' in r.text and 'IMPROVEMENT' in r.text and 'REMOVED' in r.text
    assert r.headers['cache-control']=='no-store' and 'content-security-policy' in r.headers

def test_filter(client):
    r=client.get('/operations/qualification-history/matrix?older=1&newer=2&state=REGRESSION',headers={'x-token':'yes'})
    assert r.status_code==200 and '=EVIL()' in r.text and '<td>IMPROVEMENT</td>' not in r.text
    assert client.get('/operations/qualification-history/matrix?older=1&newer=2&state=WRONG',headers={'x-token':'yes'}).status_code==422

def test_csv_injection(client):
    r=client.get('/api/v1/operations/qualification-history/matrix.csv?older=1&newer=2',headers={'x-token':'yes'})
    assert r.status_code==200
    rows=list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows)==5 and any(row['check']=="'=EVIL()" for row in rows)
    assert r.headers['content-disposition'].startswith('attachment;')

def test_invalid_order(client):
    assert client.get('/api/v1/operations/qualification-history/matrix.csv?older=2&newer=1',headers={'x-token':'yes'}).status_code==422
    assert client.get('/api/v1/operations/qualification-history/matrix.csv?older=1&newer=99',headers={'x-token':'yes'}).status_code==404
