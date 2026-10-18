"""ASGI HTTP and restart qualification; local signed tokens, no live IdP."""
import sqlite3
import pytest
from fastapi.testclient import TestClient
from qualification_oidc_http_resilience_v2243 import create_resilient_custody_oidc_app
from qualification_jwks_custody_v2241 import JWKSWitnessHandoff, receipt_for
from qualification_jwks_persistent_v2239 import PersistentJWKSRotation
from qualification_jwks_rotation_v2238 import jwks_digest
from test_qualification_oidc_production_v2237 import b64
from test_qualification_production_app_v2236 import build
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import json

S=b'W'*32; C=b'C'*32
PATH='/api/v1/operations/qualification-history/reviews'

def setup(tmp_path):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    pub=key.public_key().public_numbers()
    jwks={'keys':[{'kty':'RSA','kid':'test-key','alg':'RS256',
       'n':b64(pub.n.to_bytes((pub.n.bit_length()+7)//8,'big')),
       'e':b64(pub.e.to_bytes((pub.e.bit_length()+7)//8,'big'))}]}
    cfg=dict(issuer='https://id.example',audience='odmm',jwks=jwks,clock=lambda:1000,
             jwks_db_path=tmp_path/'jwks.db',witness_path=tmp_path/'witness.json',
             witness_secret=S,custody_ledger_path=tmp_path/'custody.db',custody_secret=C)
    state=PersistentJWKSRotation(path=cfg['jwks_db_path'],issuer=cfg['issuer'],
                                 audience=cfg['audience'],initial_jwks=jwks).state
    handoff=JWKSWitnessHandoff(ledger_path=cfg['custody_ledger_path'],
        witness_path=cfg['witness_path'],witness_secret=S,custody_secret=C)
    kw=build(tmp_path); kw.pop('authenticate')
    def app():return create_resilient_custody_oidc_app(**cfg,**kw)
    def token(**claims):
        payload=dict(iss='https://id.example',aud='odmm',exp=1500,sub='alice',roles=['qualification:read'])
        payload.update(claims)
        head=b64(json.dumps({'alg':'RS256','kid':'test-key','typ':'JWT'}).encode())
        body=b64(json.dumps(payload).encode()); data=(head+'.'+body).encode()
        return head+'.'+body+'.'+b64(key.sign(data,padding.PKCS1v15(),hashes.SHA256()))
    def get(application, tok=None):
        return TestClient(application,raise_server_exceptions=False).get(PATH,
            headers={'Authorization':'Bearer '+tok} if tok else {})
    return state,handoff,cfg,app,token,get

def confirm(state,handoff):
    witness=handoff.prepare(state)
    handoff.confirm(receipt=receipt_for(witness,custodian='independent-vault',
                    reference='test-only',custody_secret=C),current_state=state)

def test_pending_blocks_startup(tmp_path):
    state,h,_,app,_,_=setup(tmp_path); h.prepare(state)
    with pytest.raises(ValueError,match='JWKS_WITNESS_UNAVAILABLE'):app()

def test_confirmed_allows_signed_http_request(tmp_path,monkeypatch):
    state,h,_,app,token,get=setup(tmp_path);confirm(state,h)
    monkeypatch.setattr('qualification_review_portal_v2216.review_status',lambda *a,**k:{'review_status':'PENDING','events':[]})
    monkeypatch.setattr('qualification_review_portal_v2216.dossier',lambda *a,**k:{'payload_sha256':'0'*64})
    a=app(); assert get(a,token()).status_code==200
    assert get(a).status_code==401
    assert get(a,token(aud='bad')).status_code==401

def test_tamper_after_start_fails_closed_http(tmp_path):
    state,h,cfg,app,token,get=setup(tmp_path);confirm(state,h);a=app()
    with sqlite3.connect(cfg['custody_ledger_path']) as db:
        db.execute("UPDATE handoff SET state='PENDING_CUSTODY_ACK' WHERE id=1")
    r=get(a,token());assert r.status_code==503;assert r.json()['detail']=='OIDC_CUSTODY_EVIDENCE_UNVERIFIED'

def test_missing_witness_after_start_fails_closed_http(tmp_path):
    state,h,cfg,app,token,get=setup(tmp_path);confirm(state,h);a=app()
    cfg['witness_path'].unlink()
    assert get(a,token()).status_code==503

def test_restart_pending_then_confirm(tmp_path,monkeypatch):
    state,h,_,app,token,get=setup(tmp_path);w=h.prepare(state)
    with pytest.raises(ValueError):app()
    h.confirm(receipt=receipt_for(w,custodian='independent-vault',reference='test-only',custody_secret=C),current_state=state)
    monkeypatch.setattr('qualification_review_portal_v2216.review_status',lambda *a,**k:{'review_status':'PENDING','events':[]})
    monkeypatch.setattr('qualification_review_portal_v2216.dossier',lambda *a,**k:{'payload_sha256':'0'*64})
    assert get(app(),token()).status_code==200

def test_rotation_stales_custody_http(tmp_path):
    state,h,cfg,app,token,get=setup(tmp_path);confirm(state,h);a=app()
    from qualification_jwks_persistent_v2239 import PersistentJWKSRotation
    rot=PersistentJWKSRotation(path=cfg['jwks_db_path'],issuer=cfg['issuer'],audience=cfg['audience'],initial_jwks=cfg['jwks'])
    import copy
    jwks=copy.deepcopy(cfg['jwks']); jwks['keys'].append(dict(jwks['keys'][0],kid='next'))
    rot.rotate(jwks=jwks,expected_generation=0,expected_sha256=jwks_digest(jwks),expected_previous_sha256=jwks_digest(cfg['jwks']))
    assert get(a,token()).status_code==503
