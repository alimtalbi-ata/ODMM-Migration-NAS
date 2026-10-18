import io
import pytest
from odmm_registry_client_v2267 import normalize_registry_jobs, fetch_registry_jobs

DATA = {'schema':'odmm.jobs.v1','read_only':True,'items':[{'id':'J-1','state':'DONE','source':'a','target':'b'}]}

def test_real_contract():
    result = normalize_registry_jobs(DATA)
    assert result[0]['status'] == 'COMPLETED'
    assert result[0]['progress_percent'] is None

@pytest.mark.parametrize('change', [
    {'schema':'other'}, {'read_only':False}, {'items':{}},
    {'items':[{'id':'x','state':'UNKNOWN'}]},
    {'items':[{'id':'x','state':'DONE'},{'id':'x','state':'DONE'}]},
])
def test_reject(change):
    with pytest.raises(ValueError): normalize_registry_jobs({**DATA, **change})

class Response:
    status=200
    headers={'Content-Type':'application/json'}
    def __init__(self, data): self.data=io.BytesIO(data)
    def read(self,n): return self.data.read(n)
    def __enter__(self): return self
    def __exit__(self,*a): pass
class Opener:
    def open(self, request, timeout):
        assert request.full_url.endswith('/api/v1/operations/jobs?limit=200')
        assert request.get_header('Authorization') == 'Bearer 12345678'
        return Response(b'{"schema":"odmm.jobs.v1","read_only":true,"items":[]}')

def test_http_adapter():
    assert fetch_registry_jobs('https://example.org', '12345678', opener=Opener()) == []

def test_no_insecure_remote_http():
    with pytest.raises(ValueError): fetch_registry_jobs('http://example.org','12345678')
