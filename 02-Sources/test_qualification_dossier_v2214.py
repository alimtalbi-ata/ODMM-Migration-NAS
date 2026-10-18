import json
import sqlite3
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from qualification_history_v2205 import SCHEMA
from qualification_dossier_v2214 import dossier, verify_dossier, render_dossier_html, attach_qualification_dossier

@pytest.fixture
def db(tmp_path):
    p = tmp_path/'runs.db'
    with sqlite3.connect(p) as con:
        con.execute(SCHEMA)
        for i, checks in enumerate(({'auth':True,'acl':True}, {'auth':True,'acl':False}, {'auth':True,'acl':True}), 1):
            con.execute('INSERT INTO runs(recorded_at,evidence_sha256,status,browser_status,checks_json,failures_json,screenshots_json,windows_qualified) VALUES (?,?,?,?,?,?,?,0)', (f'2026-10-16T10:0{i}:00Z', f'{i:064x}', 'FAIL', 'FAIL', json.dumps(checks), '[]', '[]'))
    return p

def test_integrity_and_missing(db):
    r=dossier(db,required_checks=['auth','acl','smb'])
    assert verify_dossier(r)
    assert r['payload']['coverage']['missing_evidence']==['smb']
    assert 'RESOLVE_MISSING_EVIDENCE' in r['payload']['review']['required_actions']
    assert not r['payload']['cutover_authorized']

def test_tampering(db):
    r=dossier(db,required_checks=['auth'])
    r['payload']['coverage']['coverage_percent']=999
    assert not verify_dossier(r)
    with pytest.raises(ValueError): render_dossier_html(r)

def test_no_auto_approval(db):
    r=dossier(db,required_checks=['auth','acl'])
    assert r['payload']['review']['decision']=='PENDING_HUMAN_REVIEW'
    assert r['signature_verified'] is False

def test_html_escape(db):
    r=dossier(db,required_checks=['<script>alert(1)</script>'])
    s=render_dossier_html(r)
    assert '<script>' not in s and '&lt;script&gt;' in s

def test_routes_authorized(db):
    app=FastAPI();attach_qualification_dossier(app,authorize=lambda r:r.headers.get('x-auth')=='yes',db_path=db,required_checks=['auth','smb'])
    c=TestClient(app)
    assert c.get('/operations/qualification-history/dossier').status_code==403
    assert c.get('/api/v1/operations/qualification-history/dossier.json').status_code==403
    r=c.get('/api/v1/operations/qualification-history/dossier.json',headers={'x-auth':'yes'})
    assert r.status_code==200 and verify_dossier(r.json())
    h=c.get('/operations/qualification-history/dossier',headers={'x-auth':'yes'})
    assert h.status_code==200 and 'Content-Security-Policy' in h.headers

def test_invalid_limit(db):
    with pytest.raises(ValueError): dossier(db,required_checks=['auth'],limit=0)

def test_invalid_config(db):
    with pytest.raises(ValueError): attach_qualification_dossier(FastAPI(),authorize=lambda r:True,db_path=db,required_checks=['a','a'])
