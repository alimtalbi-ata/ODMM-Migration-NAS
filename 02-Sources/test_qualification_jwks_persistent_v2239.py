import base64
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from qualification_jwks_rotation_v2238 import jwks_digest
from qualification_jwks_persistent_v2239 import PersistentJWKSRotation

def key(kid):
    n=rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key().public_numbers()
    b=lambda x:base64.urlsafe_b64encode(x.to_bytes((x.bit_length()+7)//8,'big')).rstrip(b'=').decode()
    return {'kid':kid,'kty':'RSA','alg':'RS256','n':b(n.n),'e':b(n.e)}

@pytest.fixture
def setup(tmp_path):
    a={'keys':[key('a')]}; b={'keys':[a['keys'][0],key('b')]}
    params=dict(path=tmp_path/'jwks.db',issuer='https://id.example',audience='odmm',initial_jwks=a)
    return params,a,b

def rotate(m,a,b):
    return m.rotate(jwks=b,expected_generation=0,expected_sha256=jwks_digest(b),expected_previous_sha256=jwks_digest(a))

def test_restart_persists(setup):
    p,a,b=setup; m=PersistentJWKSRotation(**p)
    assert rotate(m,a,b)['generation']==1
    assert PersistentJWKSRotation(**p).state['key_count']==2

def test_two_instances_one_writer(setup):
    p,a,b=setup; x=PersistentJWKSRotation(**p); y=PersistentJWKSRotation(**p)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda m: attempt(m,a,b),[x,y]))
    assert sorted(results)==['JWKS_ROTATION_STALE','OK']
    assert x.state['generation']==1

def attempt(m,a,b):
    try: rotate(m,a,b); return 'OK'
    except ValueError as exc: return str(exc)

def test_corrupt_digest_fails_closed(setup):
    p,a,b=setup; m=PersistentJWKSRotation(**p)
    with sqlite3.connect(p['path']) as db: db.execute("UPDATE jwks_state SET digest='bad'")
    with pytest.raises(ValueError,match='INTEGRITY'): m.state

def test_genesis_mismatch_rejected(setup):
    p,a,b=setup; PersistentJWKSRotation(**p)
    with pytest.raises(ValueError,match='INTEGRITY'):
        PersistentJWKSRotation(**{**p,'initial_jwks':b})

def test_invalid_candidate_no_write(setup):
    p,a,b=setup; m=PersistentJWKSRotation(**p)
    with pytest.raises(ValueError): rotate(m,a,{'keys':[{'kid':'bad','kty':'oct'}]})
    assert m.state['generation']==0
