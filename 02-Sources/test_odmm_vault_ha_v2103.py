import pytest
from odmm_vault_ha_v2103 import VaultHAClient
from odmm_vault_transport_v2101 import VaultTransportError

class Fake:
    def __init__(self, name, behavior): self.name, self.behavior, self.calls = name, behavior, []
    def request(self, path, headers=None, *, payload=None):
        self.calls.append((path, payload))
        if self.behavior[self.name]: raise RuntimeError('sensitive details')
        return {'ok':self.name}

def setup(behavior=None, **kw):
    behavior = behavior or {'a':False,'b':False}
    clients=[]
    def factory(url):
        client=Fake('a' if ':8200' in url else 'b',behavior);clients.append(client);return client
    return VaultHAClient(['https://vault.example:8200','https://vault.example:8201'],client_factory=factory,**kw),clients

def test_primary_read():
    h,c=setup();assert h.request('/v1/secret/data/key')=={'ok':'a'};assert not c[1].calls

def test_read_failover():
    h,c=setup({'a':True,'b':False});assert h.request('/v1/secret/data/key')=={'ok':'b'}
    assert h.status()['metrics']['failovers']==1

def test_no_post_failover():
    h,c=setup({'a':True,'b':False})
    with pytest.raises(VaultTransportError): h.request('/v1/auth/approle/login',payload={'secret_id':'private'})
    assert not c[1].calls

def test_open_circuit_and_recovery():
    now=[100.0];h,c=setup({'a':True,'b':False},clock=lambda:now[0],failure_threshold=1,cooldown_seconds=10)
    h.request('/v1/secret/data/key');assert h.status()['available_endpoints']==1
    h.request('/v1/secret/data/key');assert len(c[0].calls)==1
    now[0]=111;h.request('/v1/secret/data/key');assert len(c[0].calls)==2

def test_all_unavailable():
    h,c=setup({'a':True,'b':True},failure_threshold=1)
    with pytest.raises(VaultTransportError): h.request('/v1/secret/data/key')
    assert h.status()['state']=='UNAVAILABLE'
    with pytest.raises(VaultTransportError): h.request('/v1/secret/data/key')
    assert h.status()['metrics']['circuit_rejections']==1

def test_no_secret_in_metrics():
    h,c=setup({'a':True,'b':True});
    with pytest.raises(VaultTransportError): h.request('/v1/auth/approle/login',payload={'secret_id':'topsecret'})
    assert 'topsecret' not in str(h.status())

@pytest.mark.parametrize('endpoints', [[],['http://vault.example'],['https://a.example','https://b.example'],['https://vault.example']*2])
def test_invalid_endpoints(endpoints):
    with pytest.raises(ValueError): VaultHAClient(endpoints)

def test_no_write_when_primary_circuit_open():
    h,c=setup({'a':True,'b':False},failure_threshold=1)
    h.request('/v1/secret/data/key')
    with pytest.raises(VaultTransportError): h.request('/v1/auth/token/renew-self',payload={})
    assert not any(p=='/v1/auth/token/renew-self' for p,_ in c[1].calls)
