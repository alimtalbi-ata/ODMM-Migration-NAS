import pytest
from odmm_ldaps_transport_v2193 import collect_authenticated_memberships, TransportError

class FakeConnection:
    def __init__(self):
        self.result={'result':0,'controls':{}}
        self.response=[]
        self.closed=False
    def search(self, **kwargs):
        self.response=[{'type':'searchResEntry','dn':'uid=alice,dc=example,dc=org',
                        'attributes':{'objectClass':['person'],'entryUUID':'alice','memberOf':[]}}]
        return True
    def unbind(self): self.closed=True

def test_injected_transport_is_not_certified():
    conn=FakeConnection()
    result=collect_authenticated_memberships(endpoint='ldaps://ldap.example.org',base_dn='dc=example,dc=org',
       bind_dn='cn=reader',password='secret',connection_factory=lambda *args:conn)
    assert result['report']['directory_authenticated'] is False
    assert result['report']['cutover_authorized'] is False
    assert result['report']['accounts']['uid=alice,dc=example,dc=org']['id']=='alice'
    assert conn.closed

@pytest.mark.parametrize('url',['ldap://ldap.example.org','ldaps://user:pass@ldap.example.org','ldaps://ldap.example.org:1636','ldaps://ldap.example.org/path'])
def test_unsafe_endpoint_rejected(url):
    with pytest.raises(TransportError):
        collect_authenticated_memberships(endpoint=url,base_dn='dc=example',bind_dn='reader',password='secret',connection_factory=lambda *args:FakeConnection())

def test_credentials_not_in_errors():
    def fail(*args): raise RuntimeError('bad secret')
    with pytest.raises(TransportError,match='LDAP_BIND_OR_TLS_FAILED') as exc:
        collect_authenticated_memberships(endpoint='ldaps://ldap.example.org',base_dn='dc=example',bind_dn='reader',password='secret',connection_factory=fail)
    assert 'secret' not in str(exc.value)
