import json
import os
import sqlite3
import pytest
from odmm_access_audit_v2184 import append_campaign, verify_audit, AuditError, digest

def campaign():
    report={'schema':'odmm.isolated-access-campaign.v2183','cases':[], 'cutover_authorized':False,'nas_qualified':False,'dedicated_account_attested':False}
    return {'report':report,'sha256':digest(report)}

def test_append_verify(tmp_path):
    p=tmp_path/'audit.db';first=append_campaign(p,campaign());second=append_campaign(p,campaign(),expected_head=first['head'])
    assert second['seq']==2
    assert verify_audit(p)['head']==second['head']
    assert not verify_audit(p)['cutover_authorized']

def test_stale_cas(tmp_path):
    p=tmp_path/'audit.db';append_campaign(p,campaign())
    with pytest.raises(AuditError,match='STALE_HEAD'): append_campaign(p,campaign(),expected_head='0'*64)
    assert verify_audit(p)['entries']==1

def test_tamper_detected(tmp_path):
    p=tmp_path/'audit.db';append_campaign(p,campaign())
    db=sqlite3.connect(p);db.execute("UPDATE audit SET payload='{}' WHERE seq=1");db.commit();db.close()
    with pytest.raises(AuditError,match='TAMPER_DETECTED'): verify_audit(p)
    with pytest.raises(AuditError,match='TAMPER_DETECTED'): append_campaign(p,campaign())

def test_forged_authorization(tmp_path):
    c=campaign();c['report']['cutover_authorized']=True;c['sha256']=digest(c['report'])
    with pytest.raises(AuditError,match='UNTRUSTED_CAMPAIGN'): append_campaign(tmp_path/'audit.db',c)

def test_bad_digest(tmp_path):
    c=campaign();c['sha256']='0'*64
    with pytest.raises(AuditError,match='UNTRUSTED_CAMPAIGN'): append_campaign(tmp_path/'audit.db',c)

def test_symlink_rejected(tmp_path):
    p=tmp_path/'audit.db';p.symlink_to(tmp_path/'other')
    with pytest.raises(AuditError,match='INVALID_DB_PATH'): append_campaign(p,campaign())
