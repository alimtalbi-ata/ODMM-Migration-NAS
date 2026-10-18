import io
import pytest
from odmm_registry_operations_v2269 import normalize_operations, fetch_operations
BASE={'schema':'odmm.operations.v1','read_only':True,'job_id':'J1','items':[{'id':'O1','job_id':'J1','state':'RUNNING','owner':'worker','epoch':3,'lease_until':1234}]}
def test_normalize():
    assert normalize_operations(BASE,'J1')[0]['epoch']==3
@pytest.mark.parametrize('patch',[{'schema':'bad'},{'read_only':False},{'job_id':'J2'},{'items':{}},{'items':[{'id':'O1','job_id':'J2','state':'DONE'}]},{'items':[{'id':'O1','job_id':'J1','state':'INVALID'}]},{'items':[{'id':'O1','job_id':'J1','state':'DONE','epoch':-1}]},{'items':[{'id':'O1','job_id':'J1','state':'DONE','owner':'x\n'}]}])
def test_invalid(patch):
    with pytest.raises(ValueError): normalize_operations({**BASE,**patch},'J1')
class Response:
    status=200
    headers={'Content-Type':'application/json'}
    def __init__(self):
        import json
        self.body=io.BytesIO(json.dumps(BASE).encode())
    def read(self,n): return self.body.read(n)
    def __enter__(self): return self
    def __exit__(self,*args): pass
class Opener:
    def open(self,request,timeout):
        assert request.full_url.endswith('/api/v1/operations/jobs/J1/operations?limit=200')
        assert request.get_header('Authorization')=='Bearer 12345678'
        return Response()
def test_fetch(): assert fetch_operations('https://example.org','12345678','J1',opener=Opener())[0]['id']=='O1'
def test_reject_http():
    with pytest.raises(ValueError): fetch_operations('http://example.org','12345678','J1')
