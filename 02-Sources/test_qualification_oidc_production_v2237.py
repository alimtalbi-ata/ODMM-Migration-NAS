"""Real cryptographic JWT tests with locally generated keys, not a live IdP."""
import base64, json
import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from qualification_oidc_production_v2237 import create_oidc_production_review_app
from test_qualification_production_app_v2236 import build

def b64(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

@pytest.fixture
def setup(tmp_path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    pub=key.public_key().public_numbers()
    jwks={'keys':[{'kty':'RSA','kid':'pinned','alg':'RS256','n':b64(pub.n.to_bytes((pub.n.bit_length()+7)//8,'big')),'e':b64(pub.e.to_bytes((pub.e.bit_length()+7)//8,'big'))}]}
    kwargs=build(tmp_path); kwargs.pop('authenticate')
    app=create_oidc_production_review_app(issuer='https://id.example',audience='odmm-review',jwks=jwks,clock=lambda:1000,**kwargs)
    def token(**updates):
        claims={'iss':'https://id.example','aud':'odmm-review','exp':1500,'sub':'alice','roles':['qualification:read']}
        claims.update(updates)
        h=b64(json.dumps({'alg':'RS256','typ':'JWT','kid':'pinned'}).encode()); p=b64(json.dumps(claims).encode())
        sig=key.sign((h+'.'+p).encode(),padding.PKCS1v15(),hashes.SHA256())
        return h+'.'+p+'.'+b64(sig)
    return TestClient(app),token

def get(client, token=None):
    return client.get('/api/v1/operations/qualification-history/reviews',headers={'Authorization':'Bearer '+token} if token else {})

def test_no_bearer(setup):
    c,t=setup; assert get(c).status_code==401

def test_signed_token_authorized(setup, monkeypatch):
    monkeypatch.setattr("qualification_review_portal_v2216.review_status", lambda *a, **k: {"review_status":"PENDING","events":[]})
    monkeypatch.setattr("qualification_review_portal_v2216.dossier", lambda *a, **k: {"payload_sha256":"0"*64})
    c,t=setup; assert get(c,t()).status_code==200

def test_bad_issuer_rejected(setup):
    c,t=setup; assert get(c,t(iss='https://evil.example')).status_code==401

def test_bad_audience_rejected(setup):
    c,t=setup; assert get(c,t(aud='wrong')).status_code==401

def test_expired_rejected(setup):
    c,t=setup; assert get(c,t(exp=999)).status_code==401

def test_untrusted_role_rejected(setup):
    c,t=setup; assert get(c,t(roles=['admin'])).status_code==401

def test_insufficient_role_rejected(setup):
    c,t=setup; assert get(c,t(roles=['qualification:prepare'])).status_code==403

def test_tampered_token_rejected(setup):
    c,t=setup; tok=t(); parts=tok.split('.'); parts[1]=b64(b'{"sub":"attacker"}')
    assert get(c,'.'.join(parts)).status_code==401

def test_write_requires_origin_and_bearer(setup):
    c,t=setup
    r=c.post('/api/v1/operations/qualification-history/reviews',headers={'Authorization':'Bearer '+t(roles=['qualification:read','qualification:write','qualification:approve'])})
    assert r.status_code in (400,403)

def test_cannot_override_authenticator(tmp_path):
    with pytest.raises(ValueError,match='OVERRIDE_FORBIDDEN'):
        create_oidc_production_review_app(issuer='https://id.example',audience='a',jwks={},authenticate=lambda r: {})
