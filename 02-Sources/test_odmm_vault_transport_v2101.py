import io
import json
import ssl
import pytest
from odmm_vault_transport_v2101 import (VaultHTTPSClient,VaultTransportError,VaultAppRoleTokenProvider,create_vault_kv2_resolver)

class Reply:
    status=200
    def __init__(self,data):self.data=data
    def __enter__(self):return self
    def __exit__(self,*a):pass
    def read(self,n):return self.data[:n]

class Fake:
    def __init__(self):self.calls=[]
    def __call__(self,request,**kw):
        assert isinstance(kw['context'],ssl.SSLContext)
        assert kw['context'].check_hostname
        self.calls.append((request.full_url,request.data,dict(request.header_items())))
        if request.full_url.endswith('/login'):
            return Reply(json.dumps({'auth':{'client_token':'short-token','lease_duration':30,'renewable':False}}).encode())
        return Reply(json.dumps({'data':{'data':{'hmac_key_hex':'ab'*32},'metadata':{'destroyed':False,'deletion_time':''}}}).encode())

@pytest.mark.parametrize('url',['http://vault.example','https://user:pass@vault.example','https://vault.example/a','https://vault.example?x=1','https://vault.example#x','localhost'])
def test_reject_insecure_urls(url):
    with pytest.raises(ValueError):VaultHTTPSClient(url)

def test_approle_kv2_roundtrip():
    fake=Fake()
    resolver=create_vault_kv2_resolver('https://vault.example',role_id_provider=lambda:'role',secret_id_provider=lambda:'secret',opener=fake)
    assert resolver('k1')==bytes.fromhex('ab'*32)
    assert len(fake.calls)==2
    assert fake.calls[0][0]=='https://vault.example/v1/auth/approle/login'
    assert b'"secret_id":"secret"' in fake.calls[0][1]
    assert fake.calls[1][2]['X-vault-token']=='short-token'

def test_no_exception_leak():
    def fail(*a,**kw):raise RuntimeError('sensitive-secret')
    client=VaultHTTPSClient('https://vault.example',opener=fail)
    with pytest.raises(VaultTransportError) as exc:client.request('/v1/secret/data/x')
    assert 'sensitive' not in str(exc.value)

def test_invalid_path_and_response_limit():
    client=VaultHTTPSClient('https://vault.example',opener=lambda *a,**kw:Reply(b'X'*2048),max_response_bytes=1024)
    with pytest.raises(ValueError):client.request('/v1/../bad')
    with pytest.raises(VaultTransportError):client.request('/v1/secret/data/x')

def test_approle_invalid_ttl():
    class Client:
        def request(self,*a,**kw):return {'auth':{'client_token':'abc','lease_duration':0,'renewable':False}}
    with pytest.raises(VaultTransportError):VaultAppRoleTokenProvider(Client(),role_id_provider=lambda:'r',secret_id_provider=lambda:'s')()

def test_no_secret_id_in_repr():
    provider=VaultAppRoleTokenProvider(object_with_request(),role_id_provider=lambda:'r',secret_id_provider=lambda:'my-secret')
    assert 'my-secret' not in repr(provider)

def object_with_request():
    class C:
        def request(self,*a,**kw):return {}
    return C()
