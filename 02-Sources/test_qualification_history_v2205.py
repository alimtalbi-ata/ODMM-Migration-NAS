import json
import pytest
from qualification_history_v2205 import ingest, history, compare


def make_evidence(path, checks=None):
    path.mkdir()
    (path/'dashboard-initial.png').write_bytes(b'example screenshot')
    import hashlib
    sha = hashlib.sha256(b'example screenshot').hexdigest()
    (path/'recette-result.json').write_text(json.dumps({'schema':'odmm-browser-acceptance-v2203','status':'PASS',
        'checks': checks or {'http':True,'security_headers':True,'filters':True}, 'console_error_count':0,
        'page_error_count':0, 'screenshots':[{'name':'dashboard-initial.png','sha256':sha}]}))


def test_history_dedup(tmp_path):
    d=tmp_path/'a'; make_evidence(d); db=tmp_path/'history.sqlite'
    a=ingest(db,d); b=ingest(db,d)
    assert a['status']=='PASS' and not a['duplicate'] and b['duplicate']
    assert len(history(db))==1 and history(db)[0]['windows_qualified'] is False


def test_regression(tmp_path):
    db=tmp_path/'h.sqlite'; a=tmp_path/'a'; b=tmp_path/'b'
    make_evidence(a); make_evidence(b, {'http':True,'security_headers':False,'filters':True})
    x=ingest(db,a); y=ingest(db,b)
    assert y['status']=='FAIL'
    diff=compare(db,x['id'],y['id'])
    assert diff['regressions']==['security_headers']
    assert 'REQUIRED_CHECKS_NOT_PASSED' in diff['new_failures']


def test_missing_fails_closed(tmp_path):
    with pytest.raises(ValueError): ingest(tmp_path/'h.sqlite',tmp_path)


def test_invalid_and_missing_comparison(tmp_path):
    db=tmp_path/'h.sqlite'; a=tmp_path/'a'; make_evidence(a)
    x=ingest(db,a)
    with pytest.raises(ValueError): compare(db,x['id'],x['id'])
    with pytest.raises(ValueError): compare(db,x['id'],999)
    with pytest.raises(ValueError): history(db,101)


def test_changed_evidence_is_new_record(tmp_path):
    db=tmp_path/'h.sqlite'; a=tmp_path/'a'; make_evidence(a)
    x=ingest(db,a)
    doc=json.loads((a/'recette-result.json').read_text()); doc['status']='FAIL'
    (a/'recette-result.json').write_text(json.dumps(doc))
    y=ingest(db,a)
    assert y['id'] != x['id'] and y['status']=='FAIL'
