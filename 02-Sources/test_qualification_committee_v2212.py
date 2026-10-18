import json
import sqlite3
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from qualification_history_v2205 import SCHEMA
from qualification_committee_v2212 import committee_report, attach_qualification_committee, render_committee_html

@pytest.fixture
def db(tmp_path):
    path=tmp_path/'history.db'
    with sqlite3.connect(path) as con:
        con.execute(SCHEMA)
        for i, checks in enumerate(({'auth':True,'navigation':False},{'auth':False,'navigation':True},{'auth':True,'navigation':True}),1):
            con.execute('INSERT INTO runs(recorded_at,evidence_sha256,status,browser_status,checks_json,failures_json,screenshots_json,windows_qualified) VALUES (?,?,?,?,?,?,?,0)',(f'2026-10-16T10:0{i}:00Z',f'{i:064x}','FAIL','FAIL',json.dumps(checks),'[]','[]'))
    return path

def test_thresholds(db):
    report=committee_report(db)
    assert report['violations']==['REGRESSIONS_EXCEEDED']
    assert report['quality_gate']=='REVIEW_REQUIRED' and not report['cutover_authorized']
    assert committee_report(db,thresholds={'max_open_failures':0,'max_regressions':1,'min_runs':3})['quality_gate']=='METRICS_WITHIN_THRESHOLDS'

def test_invalid_thresholds(db):
    for limits in ({'max_regressions':0}, {'max_open_failures':True,'max_regressions':0,'min_runs':2}, {'max_open_failures':0,'max_regressions':0,'min_runs':1}):
        with pytest.raises(ValueError): committee_report(db,thresholds=limits)

def test_routes_auth_and_csp(db):
    app=FastAPI(); attach_qualification_committee(app,authorize=lambda r:r.headers.get('x-auth')=='ok',db_path=db)
    client=TestClient(app)
    assert client.get('/operations/qualification-history/committee').status_code==403
    r=client.get('/operations/qualification-history/committee',headers={'x-auth':'ok'})
    assert r.status_code==200 and 'Content-Security-Policy' in r.headers and '●' in r.text
    r=client.get('/api/v1/operations/qualification-history/committee.json',headers={'x-auth':'ok'})
    assert r.status_code==200 and r.json()['human_approval_required']

def test_escape(db):
    with sqlite3.connect(db) as con:
        con.execute('UPDATE runs SET checks_json=? WHERE id=3',(json.dumps({'<script>alert(1)</script>':True}),))
    page=render_committee_html(committee_report(db))
    assert '<script>' not in page and '&lt;script&gt;' in page

def test_missing_db_fails_closed(tmp_path):
    with pytest.raises(HTTPException) as error: committee_report(tmp_path/'missing.db')
    assert error.value.status_code==503
