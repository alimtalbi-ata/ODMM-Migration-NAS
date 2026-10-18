import json
import sqlite3
import pytest
from fastapi import FastAPI,HTTPException
from fastapi.testclient import TestClient
from qualification_history_v2205 import SCHEMA
from qualification_coverage_v2213 import coverage_report,render_coverage_html,attach_qualification_coverage

@pytest.fixture
def db(tmp_path):
    p=tmp_path/'history.db'
    with sqlite3.connect(p) as con:
        con.execute(SCHEMA)
        for i,checks in enumerate(({'auth':True,'acl':True},{'auth':True,'acl':False},{'auth':True,'acl':True}),1):
            con.execute('INSERT INTO runs(recorded_at,evidence_sha256,status,browser_status,checks_json,failures_json,screenshots_json,windows_qualified) VALUES (?,?,?,?,?,?,?,0)',(f'2026-10-16T10:0{i}:00Z',f'{i:064x}','FAIL','FAIL',json.dumps(checks),'[]','[]'))
    return p

def test_missing_and_coverage(db):
    r=coverage_report(db,required_checks=['auth','acl','smb'],thresholds={'max_open_failures':0,'max_regressions':1,'min_runs':3})
    assert r['coverage_percent']==66.67 and r['missing_evidence']==['smb']
    assert 'MANDATORY_EVIDENCE_MISSING' in r['violations'] and not r['cutover_authorized']

def test_failed_required(db):
    with sqlite3.connect(db) as con:
        con.execute('UPDATE runs SET checks_json=? WHERE id=3',(json.dumps({'auth':False,'acl':True}),))
    r=coverage_report(db,required_checks=['auth'])
    assert r['failed_required']==['auth'] and r['quality_gate']=='REVIEW_REQUIRED'

def test_invalid_required(db):
    for x in ([],['a','a'],[''],[True],['x'*129]):
        with pytest.raises(ValueError): coverage_report(db,required_checks=x)

def test_auth_routes(db):
    app=FastAPI();attach_qualification_coverage(app,authorize=lambda r:r.headers.get('x-auth')=='yes',db_path=db,required_checks=['auth','smb'])
    c=TestClient(app)
    assert c.get('/operations/qualification-history/coverage').status_code==403
    r=c.get('/operations/qualification-history/coverage',headers={'x-auth':'yes'})
    assert r.status_code==200 and 'Content-Security-Policy' in r.headers
    assert c.get('/api/v1/operations/qualification-history/coverage.json',headers={'x-auth':'yes'}).json()['required_total']==2

def test_escape(db):
    r=coverage_report(db,required_checks=['<img src=x onerror=alert(1)>'])
    page=render_coverage_html(r)
    assert '<img' not in page and '&lt;img' in page

def test_missing_db(tmp_path):
    with pytest.raises(HTTPException) as e: coverage_report(tmp_path/'missing.db',required_checks=['auth'])
    assert e.value.status_code==503
