import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_oidc_policy_v2109 import PolicyOIDCVerifier,create_policy_oidc_vault_operations_app
from test_odmm_oidc_boundary_v2107 import keys,signed
from test_odmm_vault_observability_v2104 import Fake

@pytest.fixture
def params(keys):
    return dict(issuer='https://idp.example.org',audience='odmm-operations',jwks_provider=lambda:keys[1])

def test_valid_and_revocation(keys,params):
    v=PolicyOIDCVerifier(**params,allowed_roles={'viewer'},revocation_check=lambda j,s:False)
    assert v.verify(signed(keys,jti='request-123')).verified
    for check in [lambda j,s:True,lambda j,s:None,lambda j,s:(_ for _ in ()).throw(OSError('secret'))]:
        with pytest.raises(PermissionError,match='OIDC_IDENTITY_REJECTED'):
            PolicyOIDCVerifier(**params,revocation_check=check).verify(signed(keys,jti='request-123'))

def test_missing_jti_and_bad_roles(keys,params):
    v=PolicyOIDCVerifier(**params)
    with pytest.raises(PermissionError):v.verify(signed(keys))
    with pytest.raises(PermissionError):v.verify(signed(keys,jti='invalid jti'))
    with pytest.raises(PermissionError):PolicyOIDCVerifier(**params,allowed_roles={'auditor'}).verify(signed(keys,jti='ok'))

@pytest.mark.parametrize('claim',[{'exp':0},{'iss':'https://evil.example'},{'aud':'evil'},{'nbf':4102444800}])
def test_invalid_claims(keys,params,claim):
    with pytest.raises(PermissionError):PolicyOIDCVerifier(**params).verify(signed(keys,jti='ok',**claim))

def test_revocation_provider_outage_denies(keys,params):
    def outage(j,s):raise TimeoutError('idp down')
    with pytest.raises(PermissionError):PolicyOIDCVerifier(**params,revocation_check=outage).verify(signed(keys,jti='ok'))

def test_http_all_routes_and_multirole(monkeypatch,keys,params):
    import odmm_vault_readiness_v2100 as upstream
    monkeypatch.setattr(upstream,'create_vault_operations_app',lambda **kw:FastAPI())
    app=create_policy_oidc_vault_operations_app(**params,ha_client=Fake(),allowed_roles={'viewer','auditor'},revocation_check=lambda j,s:False)
    urls=['/api/v1/operations/vault/ha-health','/operations/vault/ha-health','/api/v1/operations/vault/ha-metrics']
    with TestClient(app) as client:
        for url in urls:
            for role in ['viewer','auditor']:
                r=client.get(url,headers={'Authorization':'Bearer '+signed(keys,jti='good',odmm_roles=[role])})
                assert r.status_code==200 and r.headers['cache-control']=='no-store'
            assert client.get(url).status_code==403
            assert client.get(url,headers={'Authorization':'Bearer '+signed(keys,jti='good',odmm_roles=['admin'])}).status_code==403
            assert client.post(url).status_code==405

def test_bad_configuration(params):
    for kw in [{'allowed_roles':{'root'}},{'revocation_check':True},{'require_jti':1}]:
        with pytest.raises(ValueError):PolicyOIDCVerifier(**params,**kw)
