import sqlite3
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from qualification_history_v2205 import SCHEMA
from qualification_insights_v2207 import attach_qualification_insights,summarize

@pytest.fixture
def client(tmp_path):
    db=tmp_path/'q.db'
    with sqlite3.connect(db) as c:
        c.execute(SCHEMA)
        for i,(status,checks,failures) in enumerate([('PASS','{"navigation":true}','[]'),('FAIL','{"navigation":false}','["navigation"]'),('NOT_EXECUTED','{}','[]')]):
            c.execute('INSERT INTO runs(recorded_at,evidence_sha256,status,browser_status,checks_json,failures_json,screenshots_json,windows_qualified) VALUES (?,?,?,?,?,?,?,0)',(f'2026-10-16T10:0{i}:00Z',str(i),status,status,checks,failures,'[]'))
    app=FastAPI();attach_qualification_insights(app,authorize=lambda r:r.headers.get('x-auth')=='yes',db_path=db)
    return TestClient(app),db

def test_access(client):
    c,_=client
    for path in ('/operations/qualification-history/insights','/api/v1/operations/qualification-history/insights','/operations/qualification-history/compare?older=1&newer=2'):
        assert c.get(path).status_code==403

def test_metrics_filters(client):
    c,_=client; h={'x-auth':'yes'}
    r=c.get('/api/v1/operations/qualification-history/insights',headers=h)
    assert (r.json()['total'],r.json()['pass'],r.json()['fail'],r.json()['not_executed'])==(3,1,1,1)
    assert r.json()['cutover_authorized'] is False
    assert c.get('/api/v1/operations/qualification-history/insights?status=FAIL',headers=h).json()['total']==1
    assert c.get('/api/v1/operations/qualification-history/insights?search=navigation',headers=h).json()['total']==1

def test_html_escape_and_csp(client):
    c,db=client; h={'x-auth':'yes'}
    with sqlite3.connect(db) as con: con.execute('UPDATE runs SET failures_json=? WHERE id=2',('["<script>alert(1)</script>"]',))
    r=c.get('/operations/qualification-history/insights?search=%3Cscript%3E',headers=h)
    assert r.status_code==200 and '<script>' not in r.text and '&lt;script&gt;' in r.text
    assert 'Content-Security-Policy' in r.headers and r.headers['cache-control']=='no-store'

def test_comparison(client):
    c,_=client; h={'x-auth':'yes'}
    r=c.get('/operations/qualification-history/compare?older=1&newer=2',headers=h)
    assert r.status_code==200 and 'navigation' in r.text and 'Régressions' in r.text
    assert c.get('/operations/qualification-history/compare?older=1&newer=1',headers=h).status_code==422
    assert c.get('/operations/qualification-history/compare?older=1&newer=99',headers=h).status_code==503

def test_invalid_filters(client):
    c,_=client;h={'x-auth':'yes'}
    for q in ('status=OTHER','limit=101','search='+('a'*121)):
        assert c.get('/operations/qualification-history/insights?'+q,headers=h).status_code==422

def test_missing_db(client):
    c,db=client;db.unlink()
    assert c.get('/operations/qualification-history/insights',headers={'x-auth':'yes'}).status_code==503

def test_reject_missing_auth(tmp_path):
    with pytest.raises(ValueError):attach_qualification_insights(FastAPI(),authorize=None,db_path=tmp_path/'x')
