import json
import pytest
from odmm_desktop_api_v2265 import fetch_jobs, validate_origin
class Response:
    status=200
    headers={'Content-Type':'application/json'}
    def __init__(self,payload): self.payload=payload
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def read(self,n): return self.payload[:n]
class Opener:
    def __init__(self,data): self.data=data
    def open(self,req,timeout):
        assert req.get_method()=='GET'
        assert req.full_url.endswith('/api/v1/jobs')
        return Response(json.dumps(self.data).encode())
def get(jobs): return fetch_jobs('https://odmm.example','secret-token',opener=Opener({'jobs':jobs}))
def test_progress(): assert get([{'id':'a','status':'running','progress_percent':42}])[0]['progress_percent']==42
def test_missing_progress(): assert get([{'id':'a','status':'running'}])[0]['progress_percent'] is None
@pytest.mark.parametrize('bad',[-1,101,True,'50',float('nan')])
def test_bad_progress(bad):
    with pytest.raises(ValueError,match='INVALID_PROGRESS'): get([{'id':'a','status':'running','progress_percent':bad}])
def test_duplicate_ids():
    with pytest.raises(ValueError,match='DUPLICATE_JOB_ID'): get([{'id':'a','status':'running'},{'id':'a','status':'failed'}])
def test_no_remote_http():
    with pytest.raises(ValueError): validate_origin('http://odmm.example')
