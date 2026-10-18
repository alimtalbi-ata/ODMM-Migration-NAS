import json
import pytest
from odmm_desktop_jobs_v2263 import load_job_status

def test_statuses(tmp_path):
    p = tmp_path/'jobs.json'
    p.write_text(json.dumps({'jobs':[{'id':'a','status':'running'},{'id':'b','status':'SOMETHING_NEW'}]}))
    assert load_job_status(p) == [{'id':'a','status':'RUNNING','source_status':'running'},{'id':'b','status':'UNKNOWN','source_status':'SOMETHING_NEW'}]

@pytest.mark.parametrize('data', [[],{}, {'jobs':'x'}, {'jobs':[{'id':'','status':'RUNNING'}]}, {'jobs':[{'id':'ok','status':1}]}, {'jobs':[{'id':'a\n','status':'RUNNING'}]}])
def test_bad_reports(tmp_path,data):
    p=tmp_path/'bad.json'; p.write_text(json.dumps(data))
    with pytest.raises(ValueError): load_job_status(p)

def test_oversize(tmp_path):
    p=tmp_path/'large.json'; p.write_bytes(b' '* (4*1024*1024+1))
    with pytest.raises(ValueError, match='REPORT_TOO_LARGE'): load_job_status(p)

def test_malformed(tmp_path):
    p=tmp_path/'bad.json'; p.write_bytes(b'{bad')
    with pytest.raises(ValueError): load_job_status(p)
