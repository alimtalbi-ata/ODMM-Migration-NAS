import json
import pytest
from odmm_desktop_api_v2264 import validate_origin, fetch_jobs

class Response:
    status=200
    headers={'Content-Type':'application/json; charset=utf-8'}
    def __init__(self, payload): self.payload=payload
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def read(self,n): return self.payload[:n]
class Opener:
    def __init__(self,payload): self.payload=payload
    def open(self,req,timeout):
        assert req.get_method()=='GET'
        assert req.full_url=='https://odmm.example/api/v1/jobs'
        assert req.get_header('Authorization')=='Bearer secret-token'
        return Response(self.payload)
@pytest.mark.parametrize('url', ['http://example.com','https://u:p@host','https://host/a','https://host?x=1','file:///tmp/x','https://host/#a'])
def test_reject_bad_origins(url):
    with pytest.raises(ValueError): validate_origin(url)
def test_local_http_allowed(): assert validate_origin('http://127.0.0.1:8090')=='http://127.0.0.1:8090'
def test_jobs():
    rows=fetch_jobs('https://odmm.example','secret-token',opener=Opener(json.dumps({'jobs':[{'id':'J-1','status':'running'},{'id':'J-2','status':'other'}]}).encode()))
    assert rows==[{'id':'J-1','status':'RUNNING'},{'id':'J-2','status':'UNKNOWN'}]
def test_invalid_response():
    with pytest.raises(ValueError): fetch_jobs('https://odmm.example','secret-token',opener=Opener(b'{bad'))
def test_limit():
    with pytest.raises(ValueError,match='REPORT_TOO_LARGE'): fetch_jobs('https://odmm.example','secret-token',opener=Opener(b'x'*(4*1024*1024+1)))
def test_token_rejected():
    with pytest.raises(ValueError): fetch_jobs('https://odmm.example','bad\nheader')
