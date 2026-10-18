import io, json, pytest
from odmm_desktop_api_v2266 import fetch_jobs
class Response:
    status=200
    headers={'Content-Type':'application/json'}
    def __init__(self, payload): self.stream=io.BytesIO(json.dumps(payload).encode())
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def read(self,n): return self.stream.read(n)
class Opener:
    def __init__(self,payload): self.payload=payload
    def open(self,request,timeout): return Response(self.payload)
def get(job): return fetch_jobs('https://example.org','abcdefgh',opener=Opener({'jobs':[job]}))[0]
def test_metrics():
    r=get({'id':'job1','status':'running','bytes_transferred':1024,'bytes_total':2048,'throughput_bytes_per_sec':42.5,'errors_count':0})
    assert r['bytes_total']==2048 and r['throughput_bytes_per_sec']==42.5
@pytest.mark.parametrize('change', [{'bytes_total':-1},{'bytes_transferred':True},{'bytes_total':1,'bytes_transferred':2},{'throughput_bytes_per_sec':float('nan')},{'errors_count':-3},{'throughput_bytes_per_sec':-1}])
def test_bad_metrics(change):
    with pytest.raises(ValueError): get({'id':'job1','status':'running',**change})
def test_optional():
    assert get({'id':'job1','status':'running'})['bytes_total'] is None
