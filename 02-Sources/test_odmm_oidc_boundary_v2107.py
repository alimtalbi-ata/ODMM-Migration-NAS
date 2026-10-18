import time
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from fastapi import FastAPI
from fastapi.testclient import TestClient
from odmm_oidc_boundary_v2107 import OIDCVerifier,create_oidc_vault_operations_app
from test_odmm_vault_observability_v2104 import Fake

@pytest.fixture
def keys():
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    import json
    public=json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    public.update(kid='key1',alg='RS256',use='sig')
    return private,{'keys':[public]}

def signed(keys,**overrides):
    now=int(time.time())
    claims=dict(iss='https://idp.example.org',aud='odmm-operations',sub='alice',iat=now,nbf=now,exp=now+300,odmm_roles=['viewer'])
    claims.update(overrides)
    return jwt.encode(claims,keys[0],algorithm='RS256',headers={'kid':'key1'})

def verifier(keys):return OIDCVerifier(issuer='https://idp.example.org',audience='odmm-operations',jwks_provider=lambda:keys[1])

def test_valid(keys):
    p=verifier(keys).verify(signed(keys))
    assert p.verified and p.subject=='alice' and p.roles==frozenset({'viewer'})

@pytest.mark.parametrize('change',[{'aud':'other'},{'iss':'https://other.example.org'},{'exp':0},{'nbf':4102444800},{'odmm_roles':['root']},{'odmm_roles':[]},{'sub':''}])
def test_rejected_claims(keys,change):
    with pytest.raises(PermissionError,match='OIDC_IDENTITY_REJECTED'):verifier(keys).verify(signed(keys,**change))

def test_kid_unknown(keys):
    token=jwt.encode({'foo':'bar'},keys[0],algorithm='RS256',headers={'kid':'unknown'})
    with pytest.raises(PermissionError):verifier(keys).verify(token)

def test_jwks_missing(keys):
    with pytest.raises(PermissionError):OIDCVerifier(issuer='https://idp.example.org',audience='odmm-operations',jwks_provider=lambda:{'keys':[]}).verify(signed(keys))

def test_oidc_http_routes(monkeypatch,keys):
    import odmm_vault_readiness_v2100 as mod
    monkeypatch.setattr(mod,'create_vault_operations_app',lambda **kwargs:FastAPI())
    app=create_oidc_vault_operations_app(issuer='https://idp.example.org',audience='odmm-operations',jwks_provider=lambda:keys[1],ha_client=Fake())
    urls=['/api/v1/operations/vault/ha-health','/operations/vault/ha-health','/api/v1/operations/vault/ha-metrics']
    with TestClient(app) as client:
        for url in urls:
            assert client.get(url).status_code==403
            assert client.get(url,headers={'Authorization':'Bearer invalid'}).status_code==403
            r=client.get(url,headers={'Authorization':'Bearer '+signed(keys)})
            assert r.status_code==200 and r.headers['cache-control']=='no-store'
            assert client.post(url,headers={'Authorization':'Bearer '+signed(keys)}).status_code==405

def test_malformed_configuration(keys):
    with pytest.raises(ValueError):OIDCVerifier(issuer='http://idp.example.org',audience='odmm-operations',jwks_provider=lambda:keys[1])
