import copy
import sqlite3
import threading
import pytest
from odmm_campaign_history_v2096 import CampaignHistory
from odmm_campaign_history_v2096 import canonical as campaign_canonical
import hashlib

def report(cid='demo',n=1):
    d={'schema':'odmm.campaign.v2095','campaign_id':cid,'status':'BLOCKED','cutover_authorized':False,'report_count':n,'submitted_count':n,'reports':[],'blockers':['INDEPENDENT_APPROVAL_REQUIRED'],'limitations':[]}
    d['sha256']=hashlib.sha256(campaign_canonical(d)).hexdigest()
    return d

def test_append_and_timeline(tmp_path):
    h=CampaignHistory(tmp_path/'history.db'); a=h.append(report(),expected_version=0)
    assert a['version']==1
    h.append(report(n=2),expected_version=1)
    t=CampaignHistory(tmp_path/'history.db').timeline('demo')
    assert t['version']==2 and t['events'][1]['report_count']==2 and not t['cutover_authorized']

def test_version_conflict_and_duplicate(tmp_path):
    h=CampaignHistory(tmp_path/'h.db');h.append(report(),expected_version=0)
    with pytest.raises(ValueError,match='VERSION_CONFLICT'):h.append(report(n=2),expected_version=0)
    with pytest.raises(ValueError,match='DUPLICATE_REPORT'):h.append(report(),expected_version=1)

def test_invalid_digest(tmp_path):
    h=CampaignHistory(tmp_path/'h.db');r=report();r['report_count']=500
    with pytest.raises(ValueError,match='INVALID_CAMPAIGN_REPORT'):h.append(r,expected_version=0)

def test_tamper(tmp_path):
    p=tmp_path/'h.db';h=CampaignHistory(p);h.append(report(),expected_version=0)
    with sqlite3.connect(p) as db:db.execute('UPDATE campaign_history SET event_hash=?',('f'*64,))
    with pytest.raises(ValueError,match='HISTORY_INTEGRITY_FAILURE'):h.timeline('demo')

def test_concurrent_conflict(tmp_path):
    p=tmp_path/'h.db';h=CampaignHistory(p); results=[]
    def task(n):
        try:results.append(h.append(report(n=n),expected_version=0))
        except ValueError as e:results.append(str(e))
    ts=[threading.Thread(target=task,args=(n,)) for n in range(1,9)]
    for t in ts:t.start()
    for t in ts:t.join()
    assert len([x for x in results if isinstance(x,dict)])==1
    assert h.timeline('demo')['version']==1

def test_campaign_isolation(tmp_path):
    h=CampaignHistory(tmp_path/'h.db');h.append(report('a'),expected_version=0)
    assert h.timeline('b')['version']==0
    with pytest.raises(ValueError,match='CAMPAIGN_INVALID'):h.timeline('../etc')
