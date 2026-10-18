import pytest
from odmm_vault_session_v2102 import VaultSession, create_managed_vault_resolver
from odmm_vault_transport_v2101 import VaultTransportError

class Fake:
    def __init__(self, renewable=True):
        self.calls=[]; self.renewable=renewable; self.fail_renew=False
    def request(self, path, headers=None, *, payload=None):
        self.calls.append((path, headers, payload))
        if path.endswith('renew-self'):
            if self.fail_renew: raise RuntimeError('secret')
            return {'auth':{'client_token':'new-token','lease_duration':100,'renewable':True}}
        return {'auth':{'client_token':'token','lease_duration':100,'renewable':self.renewable}}

def test_cached_token_and_renewal():
    t=[0]; fake=Fake(); session=VaultSession(fake,role_id_provider=lambda:'role',secret_id_provider=lambda:'secret',clock=lambda:t[0])
    assert session()=='token'; assert session()=='token'; assert len(fake.calls)==1
    t[0]=75; assert session()=='new-token'; assert fake.calls[-1][0].endswith('renew-self')
    assert session.status()['last_action']=='RENEW'
    assert 'token' not in str(session.status())

def test_renew_failure_reauthenticates():
    t=[0]; fake=Fake(); session=VaultSession(fake,role_id_provider=lambda:'r',secret_id_provider=lambda:'s',clock=lambda:t[0]);session()
    fake.fail_renew=True; t[0]=90
    assert session()=='token'; assert len(fake.calls)==3

def test_expired_never_renews():
    t=[0]; fake=Fake(); session=VaultSession(fake,role_id_provider=lambda:'r',secret_id_provider=lambda:'s',clock=lambda:t[0]);session()
    t[0]=101; assert session()=='token'; assert len(fake.calls)==2
    assert fake.calls[-1][0].endswith('/login')

def test_nonrenewable_relogin():
    t=[0]; fake=Fake(False); session=VaultSession(fake,role_id_provider=lambda:'r',secret_id_provider=lambda:'s',clock=lambda:t[0]);session()
    t[0]=80;session();assert len(fake.calls)==2

def test_fail_closed_and_redaction():
    class Broken:
        def request(self,*a,**kw):raise RuntimeError('my-secret')
    session=VaultSession(Broken(),role_id_provider=lambda:'r',secret_id_provider=lambda:'s')
    with pytest.raises(VaultTransportError) as err:session()
    assert 'my-secret' not in str(err.value)
    assert session.status()['state']=='UNAVAILABLE'
    assert session.status()['cutover_authorized'] is False

def test_invalidate():
    fake=Fake();session=VaultSession(fake,role_id_provider=lambda:'r',secret_id_provider=lambda:'s');session();session.invalidate()
    assert session.status()['state']=='UNAVAILABLE';session();assert len(fake.calls)==2

@pytest.mark.parametrize('margin',[-1,601,True,1.1])
def test_invalid_margin(margin):
    with pytest.raises(ValueError):VaultSession(Fake(),role_id_provider=lambda:'r',secret_id_provider=lambda:'s',renew_margin=margin)

def test_reject_bad_ttl():
    class Bad:
        def request(self,*a,**kw):return {'auth':{'client_token':'token','lease_duration':90000,'renewable':True}}
    session=VaultSession(Bad(),role_id_provider=lambda:'r',secret_id_provider=lambda:'s')
    with pytest.raises(VaultTransportError):session()

def test_managed_factory():
    import json
    class Response:
        status=200
        def __init__(self,data):self.data=data
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def read(self,n):return self.data[:n]
    def opener(request,**kw):
        if request.full_url.endswith('/login'):
            return Response(json.dumps({'auth':{'client_token':'t','lease_duration':100,'renewable':True}}).encode())
        return Response(json.dumps({'data':{'data':{'hmac_key_hex':'cd'*32},'metadata':{'destroyed':False,'deletion_time':''}}}).encode())
    resolver,session=create_managed_vault_resolver('https://vault.example',role_id_provider=lambda:'r',secret_id_provider=lambda:'s',opener=opener)
    assert resolver('key')==bytes.fromhex('cd'*32)
    assert session.status()['state']=='ACTIVE'
